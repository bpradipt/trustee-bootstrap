#!/usr/bin/env bash
# kind + Kata (qemu-coco-dev, runtime-rs) + swtpm. The guest Attestation
# Agent uses the TPM attester, backed by one swtpm per pod VM.
#
#   kind-kata-swtpm.sh up       get the guest artifacts, create the cluster
#   kind-kata-swtpm.sh verify   run the pinned KBS and a test pod, check
#                               that TPM evidence is accepted and that PCR8
#                               holds the Init-Data digest
#   kind-kata-swtpm.sh down     delete the cluster and stop the KBS
#   kind-kata-swtpm.sh publish  build and push the e2e guest image, unless
#                               the registry has it (guest-build.sh)
#
# Every step is idempotent. Built artifacts are cached in $E2E_CACHE.
# Versions come from versions.yaml; docs/upstream-pins.md says why.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$script_dir/../.." && pwd)

info() { echo "[kind-kata-swtpm] $*" >&2; }
die() { echo "[kind-kata-swtpm] ERROR: $*" >&2; exit 1; }

# pin <key>: a value from versions.yaml.
pin() {
	awk -v k="$1:" '$1 == k { print $2; found = 1 } END { exit !found }' "$repo/versions.yaml" ||
		die "versions.yaml has no $1"
}

# --- pins (versions.yaml) ----------------------------------------------------
KATA_TAG=$(pin kata_tag)
KATA_COMMIT=$(pin kata_commit)
KATA_STATIC_SHA256=$(pin kata_static_sha256)
KERNEL_VERSION=$(pin kernel_version)
GC_TAG=$(pin gc_tag)
GC_COMMIT=$(pin gc_commit)
COCO_EXTENSION_IMAGE=$(pin coco_extension_image)
KBS_IMAGE=$(pin kbs_image)
KIND_VERSION=$(pin kind_version)
KIND_SHA256=$(pin kind_sha256)
KIND_NODE_IMAGE=$(pin kind_node_image)
BUILDER_IMAGE=$(pin builder_image)
PROBE_IMAGE=$(pin probe_image)
RUST_TOOLCHAIN=$(pin rust_toolchain)

# --- knobs -------------------------------------------------------------------
CLUSTER=${E2E_CLUSTER:-trustee-bootstrap}
E2E_CACHE=${E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/trustee-bootstrap-e2e}
GUEST_MEMORY_MB=${E2E_GUEST_MEMORY_MB:-1024}
RUNTIME_CLASS=kata-qemu-coco-dev-tpm
ENGINE=${E2E_ENGINE:-$(command -v docker >/dev/null && echo docker || echo podman)}

src=$E2E_CACHE/src
out=$E2E_CACHE/out

# Root for the container engine. kind needs a rootful engine for /dev/kvm.
# rootsudo drops XDG_RUNTIME_DIR: where sudo keeps it (GitHub runners),
# root's crun would create $XDG_RUNTIME_DIR/crun as root and break the
# user's rootless podman afterwards.
rootsudo() { sudo env -u XDG_RUNTIME_DIR "$@"; }
eng() { if [[ $ENGINE == podman ]]; then rootsudo podman "$@"; else docker "$@"; fi; }
node() { eng exec -i "$CLUSTER-control-plane" "$@"; }

# shellcheck source=guest-build.sh
source "$script_dir/guest-build.sh"

host_deps() {
	command -v apt-get >/dev/null || die "install curl, kmod, patch, python3 and zstd by hand (see host_deps)"
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
		curl kmod patch python3 zstd >/dev/null
	# The pod VM needs vsock and vhost-net from the host kernel.
	sudo modprobe -a vhost_vsock vhost_net tun
	[[ -e /dev/kvm ]] || die "no /dev/kvm: the pod VMs need KVM (nested virtualization in a VM)"
}

kind() {
	local bin=$E2E_CACHE/bin/kind
	if [[ ! -x $bin ]]; then
		mkdir -p "${bin%/*}"
		curl -fsSLo "$bin.tmp" "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64"
		echo "$KIND_SHA256  $bin.tmp" | sha256sum -c --quiet
		chmod +x "$bin.tmp" && mv "$bin.tmp" "$bin"
	fi
	if [[ $ENGINE == podman ]]; then rootsudo KIND_EXPERIMENTAL_PROVIDER=podman "$bin" "$@"; else "$bin" "$@"; fi
}

kc() { node kubectl --kubeconfig=/etc/kubernetes/admin.conf "$@"; }

install_cluster() {
	kind get clusters 2>/dev/null | grep -qx "$CLUSTER" ||
		kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s
}

# Distribution QEMU and swtpm inside the node, the swtpm template, the Kata
# files, the containerd runtime and the RuntimeClass.
install_kata() {
	local cfg=/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-coco-dev-tpm.toml
	local verity
	verity=$(sudo cat "$out/ext/root_hash_coco-extension.txt")
	# The runtime-rs shim talks to systemd over D-Bus to place the sandbox in
	# its cgroup; the kind node ships without a D-Bus daemon.
	node bash -c 'command -v swtpm >/dev/null && command -v qemu-system-x86_64 >/dev/null && [[ -S /run/dbus/system_bus_socket ]] || {
		apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
			dbus qemu-system-x86 swtpm swtpm-tools tpm2-tools >/dev/null && systemctl start dbus; }'
	provision_swtpm
	node mkdir -p /opt/kata/bin /opt/kata/runtime-rs/bin /opt/kata/share/kata-containers "${cfg%/*}"
	eng cp "$out/kata/containerd-shim-kata-v2" "$CLUSTER-control-plane:/opt/kata/runtime-rs/bin/"
	eng cp "$out/kata/kata-ubuntu-resolute.image" "$CLUSTER-control-plane:/opt/kata/share/kata-containers/kata-containers.img"
	eng cp "$out/vmlinuz-tpm" "$CLUSTER-control-plane:/opt/kata/share/kata-containers/vmlinuz-tpm"
	sudo cat "$out/ext/kata-containers-coco-extension.img" |
		node dd status=none of=/opt/kata/share/kata-containers/coco-extension-tpm.img
	eng cp "$script_dir/qemu-swtpm" "$CLUSTER-control-plane:/opt/kata/bin/qemu-swtpm"
	sed -e '0,/^path = /s|^path = .*|path = "/opt/kata/bin/qemu-swtpm"|' \
		-e 's|^valid_hypervisor_paths = .*|valid_hypervisor_paths = ["/opt/kata/bin/qemu-swtpm"]|' \
		-e 's|^kernel = .*|kernel = "/opt/kata/share/kata-containers/vmlinuz-tpm"|' \
		-e "s|^default_memory = .*|default_memory = $GUEST_MEMORY_MB|" \
		-e 's|^experimental = .*|experimental = ["force_guest_pull"]|' \
		-e 's|^path = "/opt/kata/share/kata-containers/kata-containers-coco-extension.img"|path = "/opt/kata/share/kata-containers/coco-extension-tpm.img"|' \
		-e "s|^verity_params = .*|verity_params = \"$verity\"|" \
		"$out/kata/configuration-qemu-coco-dev-runtime-rs.toml" | node dd status=none of="$cfg"
	node grep -q '^experimental = \["force_guest_pull"\]' "$cfg" || die "config edit failed"
	node grep -q '^path = "/opt/kata/share/kata-containers/coco-extension-tpm.img"' "$cfg" || die "config edit failed"

	if ! node grep -q "runtimes.$RUNTIME_CLASS\]" /etc/containerd/config.toml; then
		# kind writes a version 2 config; version 3 renamed the CRI plugin.
		local cri="'io.containerd.grpc.v1.cri'"
		node grep -q '^version = 3' /etc/containerd/config.toml && cri="'io.containerd.cri.v1.runtime'"
		node tee -a /etc/containerd/config.toml >/dev/null <<-EOF

			[plugins.$cri.containerd.runtimes.$RUNTIME_CLASS]
			  runtime_type = "io.containerd.kata.v2"
			  runtime_path = "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
			  privileged_without_host_devices = true
			  pod_annotations = ["io.katacontainers.*"]
			[plugins.$cri.containerd.runtimes.$RUNTIME_CLASS.options]
			  ConfigPath = "$cfg"
		EOF
		node systemctl restart containerd
	fi
	kc apply -f - >/dev/null <<-EOF
		apiVersion: node.k8s.io/v1
		kind: RuntimeClass
		metadata:
		  name: $RUNTIME_CLASS
		handler: $RUNTIME_CLASS
	EOF
}

# One swtpm state with an EK (swtpm_setup persists it at 0x81010001) and an
# AK at 0x81010002, where the TPM attester looks. Every pod VM starts from a
# copy, so all pods share this AK.
provision_swtpm() {
	node test -f /opt/kata-swtpm/ak.pem && return
	info "provisioning the swtpm template"
	# shellcheck disable=SC2016 # expands in the node
	node bash -euo pipefail -c '
		t=/opt/kata-swtpm/template
		rm -rf /opt/kata-swtpm && mkdir -p $t
		swtpm_setup --tpm2 --tpmstate $t --createek --pcr-banks sha256 >/dev/null
		swtpm socket --tpm2 --tpmstate dir=$t --server type=tcp,port=2321 \
			--ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --daemon
		export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
		cd /opt/kata-swtpm
		tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pem -f pem >/dev/null
		tpm2_evictcontrol -c ak.ctx 0x81010002 >/dev/null
		swtpm_ioctl --tcp 127.0.0.1:2322 -s
		rm -f ak.ctx'
}

# --- verify ------------------------------------------------------------------
# Test-only KBS: plain HTTP, open admin API, bound to the kind gateway. Ticket
# 05 owns the secure Operator Verifier config.
KBS_NAME=$CLUSTER-kbs
RESOURCE=default/tpm/probe

kbs_up() {
	local gw=$1 dir=$E2E_CACHE/kbs
	mkdir -p "$dir"
	cat >"$dir/kbs.toml" <<-EOF
		[http_server]
		sockets = ["$gw:8080"]
		insecure_http = true
		[attestation_token]
		insecure_header_jwk = true
		[attestation_service]
		type = "coco_as_builtin"
		[attestation_service.attestation_token_broker]
		duration_min = 5
		[attestation_service.rvps_config]
		type = "BuiltIn"
		[admin]
		authorization_mode = "InsecureAllowAll"
		[storage_backend]
		storage_type = "LocalFs"
		[storage_backend.backends.local_fs]
		dir_path = "/opt/confidential-containers/storage"
		[[plugins]]
		name = "resource"
		storage_backend_type = "kvstorage"
	EOF
	eng rm -f "$KBS_NAME" >/dev/null 2>&1 || true
	eng run -d --name "$KBS_NAME" --network host -e RUST_LOG=debug -v "$dir:/etc/kbs:ro" \
		"$KBS_IMAGE" /usr/local/bin/kbs --config-file /etc/kbs/kbs.toml >/dev/null
	for _ in $(seq 30); do
		curl -fs -o /dev/null "http://$gw:8080/kbs/v0/resource-policy" && return
		sleep 1
	done
	die "KBS did not start: $(eng logs "$KBS_NAME" 2>&1 | tail -5)"
}

# kbs_post <path> <body>
kbs_post() { curl -fsS -X POST -H 'Content-Type: application/json' --data-binary "$2" "$KBS_URL/kbs/v0/$1"; }

b64() { base64 -w0; }

# initdata <kbs url> <extra line>: an Init-Data TOML that points AA and CDH at
# the KBS. The extra line changes the digest for the negative test.
initdata() {
	cat <<-EOF
		version = "0.1.0"
		algorithm = "sha256"
		[data]
		"aa.toml" = '''
		[eventlog_config]
		init_pcr = 17
		enable_eventlog = false
		[token_configs.kbs]
		url = "$1"
		'''
		"cdh.toml" = '''
		socket = "unix:///run/confidential-containers/cdh.sock"
		credentials = []
		[kbc]
		name = "cc_kbc"
		url = "$1"
		'''
		$2
	EOF
}

# tls_pair <dir> <host>: Trustee's HTTPS key and a self-signed leaf
# certificate that names host, as tls.key and tls.crt in dir. The guest's
# rustls and the sealed-config checks both refuse a CA certificate.
tls_pair() {
	openssl ecparam -name prime256v1 -genkey -noout -out "$1/tls.key"
	openssl req -new -key "$1/tls.key" -subj "/CN=$2" |
		openssl x509 -req -signkey "$1/tls.key" -days 2 -out "$1/tls.crt" -extfile <(
			printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$2"
		) 2>/dev/null
}

# Expected PCR8 after the AA extends it once with the Init-Data digest.
pcr8_for() {
	python3 -c 'import hashlib,sys; d=hashlib.sha256(sys.stdin.buffer.read()).digest(); print(hashlib.sha256(bytes(32)+d).hexdigest())'
}

# probe_pod <name> <initdata>: the manifest of a pod that asks its CDH for
# $RESOURCE and prints what it got, or DENIED.
probe_pod() {
	local annotation
	annotation=$(printf '%s' "$2" | gzip -9 | b64)
	cat <<-EOF
		apiVersion: v1
		kind: Pod
		metadata:
		  name: $1
		  annotations:
		    io.katacontainers.config.hypervisor.cc_init_data: "$annotation"
		spec:
		  runtimeClassName: $RUNTIME_CLASS
		  restartPolicy: Never
		  containers:
		  - name: probe
		    image: $PROBE_IMAGE
		    command: ["sh", "-c", "wget -qO- http://127.0.0.1:8006/cdh/resource/$RESOURCE 2>/dev/null || echo DENIED"]
	EOF
}

# run_probe <name> <initdata>: runs probe_pod's pod; prints what it got.
run_probe() {
	local name=$1
	kc delete pod "$name" --ignore-not-found --wait >/dev/null
	probe_pod "$name" "$2" | kc apply -f - >/dev/null
	kc wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$name" --timeout=300s >/dev/null ||
		die "$name did not finish: $(kc describe pod "$name" | tail -15)"
	kc logs "$name"
}

verify() {
	local gw ak pcr8 bad_pcr8 got claims
	gw=$(node ip -4 route show default | awk '{print $3}')
	KBS_URL=http://$gw:8080
	kbs_up "$gw"
	# The verifier claims carry the AK as base64 DER, which is the PEM body.
	ak=$(node sed '/-----/d' /opt/kata-swtpm/ak.pem | tr -d '\n')
	local good bad
	good=$(initdata "$KBS_URL" "")
	bad=$(initdata "$KBS_URL" "# changed")
	pcr8=$(printf '%s' "$good" | pcr8_for)
	bad_pcr8=$(printf '%s' "$bad" | pcr8_for)

	kbs_post reference-value "$(printf '{"version":"0.1.0","type":"sample","payload":"%s"}' \
		"$(printf '{"trusted_aks":["%s"],"tpm_pcr11":["%s"]}' "$ak" "$(printf '0%.0s' $(seq 64))" | b64)")"
	kbs_post resource-policy "$(printf '{"policy":"%s"}' "$(sed "s/@PCR8@/$pcr8/" "$script_dir/resource-policy.rego" | b64 | tr '+/' '-_' | tr -d '=')")"
	printf 'tpm-probe-ok' | curl -fsS -X POST --data-binary @- "$KBS_URL/kbs/v0/resource/$RESOURCE"

	got=$(run_probe tpm-probe "$good")
	[[ $got == tpm-probe-ok ]] || die "matching Init-Data: got '$got'"
	info "matching Init-Data: resource released"
	claims=$(eng logs "$KBS_NAME" 2>&1 | grep -o '"init_data": *"[0-9a-f]*"' | sort -u)
	grep -q "$pcr8" <<<"$claims" || die "PCR8 $pcr8 not in claims: $claims"
	info "verifier claim init_data (PCR8) = $pcr8 = sha256(0^32 || sha256(Init-Data))"

	got=$(run_probe tpm-probe-bad "$bad")
	[[ $got == DENIED ]] || die "changed Init-Data: got '$got'"
	claims=$(eng logs "$KBS_NAME" 2>&1 | grep -o '"init_data": *"[0-9a-f]*"' | sort -u)
	grep -q "$bad_pcr8" <<<"$claims" || die "PCR8 $bad_pcr8 not in claims: $claims"
	info "changed Init-Data: resource denied, claim init_data = $bad_pcr8"
	kc delete pod tpm-probe tpm-probe-bad --wait=false >/dev/null
	info "PASS"
}

up() {
	host_deps
	guest
	install_cluster
	install_kata
	info "ready: runtimeClassName: $RUNTIME_CLASS"
}

down() {
	eng rm -f "$KBS_NAME" >/dev/null 2>&1 || true
	kind delete cluster --name "$CLUSTER"
}

main() {
	case "${1:-}" in
	up) up ;;
	verify) verify ;;
	down) down ;;
	publish) publish ;;
	# Single steps, for debugging: guest, build_kernel, build_aa, ...
	guest | build_* | install_* | provision_*) "$1" ;;
	*) die "usage: $0 up|verify|down|publish" ;;
	esac
}

# Other e2e tests source this file for its functions.
[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
