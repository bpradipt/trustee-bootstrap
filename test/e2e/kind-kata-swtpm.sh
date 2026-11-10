#!/usr/bin/env bash
# kind + Kata (qemu-coco-dev, runtime-rs) + swtpm. The guest Attestation
# Agent uses the TPM attester, backed by one swtpm per pod VM.
#
#   kind-kata-swtpm.sh up       build what is missing, create the cluster
#   kind-kata-swtpm.sh verify   run the pinned KBS and a test pod, check
#                               that TPM evidence is accepted and that PCR8
#                               holds the Init-Data digest
#   kind-kata-swtpm.sh down     delete the cluster and stop the KBS
#
# Every step is idempotent. Built artifacts are cached in $E2E_CACHE.
# Versions come from docs/upstream-pins.md.
set -euo pipefail

# --- pins (docs/upstream-pins.md) -------------------------------------------
KATA_TAG=4.2.0
KATA_COMMIT=c7351e797efff8bfc6bd73da0eb1909be12e2cfe
KATA_STATIC_SHA256=b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8
# Kata 4.2.0 versions.yaml: assets.kernel.version
KERNEL_VERSION=6.18.35
GC_TAG=v0.22.0
GC_COMMIT=eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a
COCO_EXTENSION_IMAGE=ghcr.io/confidential-containers/guest-components/coco-extension:eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a-ubuntu26.04@sha256:e10ac1d0b915100f8212bb0be4f28669ac80588b3ba922c4580a36d23c5fb47a
KBS_IMAGE=ghcr.io/confidential-containers/key-broker-service:built-in-as-v0.22.0@sha256:c1960cb4df0b1bdc0e4309f97dc65b0a1a777a92dabb2211acb45542f906c625
KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KIND_NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
# Same Ubuntu release as the Kata 4.2.0 guest rootfs (resolute).
BUILDER_IMAGE=docker.io/library/ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
# Pulled inside the pod VM by the verify probe.
PROBE_IMAGE=docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
# guest-components v0.22.0 rust-toolchain.toml
RUST_TOOLCHAIN=1.95.0

# --- knobs -------------------------------------------------------------------
CLUSTER=${E2E_CLUSTER:-trustee-bootstrap}
E2E_CACHE=${E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/trustee-bootstrap-e2e}
GUEST_MEMORY_MB=${E2E_GUEST_MEMORY_MB:-1024}
RUNTIME_CLASS=kata-qemu-coco-dev-tpm
ENGINE=${E2E_ENGINE:-$(command -v docker >/dev/null && echo docker || echo podman)}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
src=$E2E_CACHE/src
out=$E2E_CACHE/out

info() { echo "[kind-kata-swtpm] $*" >&2; }
die() { echo "[kind-kata-swtpm] ERROR: $*" >&2; exit 1; }

# Root for the container engine. kind needs a rootful engine for /dev/kvm.
eng() { if [[ $ENGINE == podman ]]; then sudo podman "$@"; else docker "$@"; fi; }
node() { eng exec -i "$CLUSTER-control-plane" "$@"; }

# clone_at <url> <tag> <commit> <dir> [sparse paths...]
clone_at() {
	local url=$1 tag=$2 commit=$3 dir=$4
	shift 4
	if [[ ! -d $dir/.git ]]; then
		git clone -q --depth 1 --branch "$tag" --filter=blob:none ${1:+--sparse} "$url" "$dir" 2>/dev/null
		[[ $# -eq 0 ]] || git -C "$dir" sparse-checkout set --skip-checks "$@"
	fi
	[[ $(git -C "$dir" rev-parse HEAD) == "$commit" ]] || die "$dir is not at $commit"
}

host_deps() {
	command -v apt-get >/dev/null || die "install the build tools by hand (see host_deps)"
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
		bc bison build-essential cpio cryptsetup-bin curl erofs-utils flex git kmod \
		libelf-dev libssl-dev parted patch python3 rsync zstd >/dev/null
	# The pod VM needs vsock and vhost-net from the host kernel.
	sudo modprobe -a vhost_vsock vhost_net tun
	[[ -e /dev/kvm ]] || die "no /dev/kvm: the pod VMs need KVM (nested virtualization in a VM)"
}

# The Kata 4.2.0 guest kernel has no TPM driver. Rebuild it with Kata's own
# build-kernel.sh and fragments (same flags as kata-deploy-binaries.sh
# install_kernel on x86_64), plus kernel-tpm.conf.
build_kernel() {
	[[ -f $out/vmlinuz-tpm ]] && return
	info "building the Kata guest kernel with TPM drivers"
	clone_at https://github.com/kata-containers/kata-containers "$KATA_TAG" "$KATA_COMMIT" \
		"$src/kata" tools/packaging/kernel tools/packaging/scripts
	cp "$script_dir/kernel-tpm.conf" "$src/kata/tools/packaging/kernel/configs/fragments/x86_64/tpm.conf"
	local b=$E2E_CACHE/kernel-build kb="$src/kata/tools/packaging/kernel/build-kernel.sh"
	local args=(-a x86_64 -v "$KERNEL_VERSION" -u https://cdn.kernel.org/pub/linux/kernel/v6.x/ -x -m)
	mkdir -p "$b" "$out"
	(cd "$b" && "$kb" "${args[@]}" -f setup && "$kb" "${args[@]}" build)
	grep -q '^CONFIG_TCG_CRB=y' "$b"/kata-linux-*/.config || die "TPM drivers missing from kernel config"
	cp "$b"/kata-linux-*/arch/x86/boot/bzImage "$out/vmlinuz-tpm"
	rm -rf "$b"
}

# The stock coco-extension AA is built with snp and tdx attesters only. Build
# the pinned AA with tpm-attester on the guest's Ubuntu release, and keep its
# non-glibc libraries (tss2, openssl) next to it, as assemble-rootfs.sh does
# for the NVIDIA variant. Everything except the outputs stays in the
# container.
build_aa() {
	[[ -f $out/aa/attestation-agent ]] && return
	info "building attestation-agent with tpm-attester"
	clone_at https://github.com/confidential-containers/guest-components "$GC_TAG" "$GC_COMMIT" "$src/gc"
	mkdir -p "$out/aa"
	# shellcheck disable=SC2016 # expands in the container
	eng run --rm -v "$src/gc:/src:ro" -v "$out/aa:/out" -e RUST_TOOLCHAIN="$RUST_TOOLCHAIN" \
		-e OWNER="$(id -u):$(id -g)" "$BUILDER_IMAGE" bash -euo pipefail -c '
		export DEBIAN_FRONTEND=noninteractive PATH=/root/.cargo/bin:$PATH
		apt-get update -qq
		apt-get install -y -qq --no-install-recommends ca-certificates clang cmake curl g++ gcc \
			libclang-dev libssl-dev libtss2-dev make perl pkg-config protobuf-compiler >/dev/null
		curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
		cp -a /src /build
		make -C /build/attestation-agent ttrpc=true ATTESTER=tpm-attester
		aa=/build/target/x86_64-unknown-linux-gnu/release/attestation-agent
		strip "$aa"
		install -D -m0755 "$aa" /out/attestation-agent
		{ ldd "$aa"; echo "/usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0 x"; } |
			grep -o "/[^ ]*" | while read -r lib; do
				case ${lib##*/} in ld-linux-* | libc.so.* | libdl.so.* | libm.so.* | libpthread.so.* | librt.so.*) continue ;; esac
				install -D -m0755 "$lib" "/out/lib/${lib##*/}"
			done
		chown -R "$OWNER" /out'
	eng rmi "$BUILDER_IMAGE" >/dev/null || true
}

# The pinned coco-extension payload with the AA swapped for build_aa's, packed
# into a dm-verity extension image by guest-components' own script.
build_extension() {
	[[ -f $out/ext/kata-containers-coco-extension.img ]] && return
	build_aa
	info "building the coco extension image with the tpm AA"
	local root=$E2E_CACHE/ext-rootfs c
	sudo rm -rf "$root" && mkdir -p "$root"
	c=$(eng create "$COCO_EXTENSION_IMAGE" /x)
	eng export "$c" | sudo tar -x -C "$root"
	eng rm "$c" >/dev/null
	eng rmi "$COCO_EXTENSION_IMAGE" >/dev/null || true
	sudo install -m0755 "$out/aa/attestation-agent" "$root/usr/local/bin/attestation-agent"
	sudo install -m0755 -D -t "$root/usr/local/lib" "$out/aa/lib/"*
	local manifest=$root/etc/kata-extensions/components.toml
	grep -q '^  path = "usr/local/bin/attestation-agent"$' "$manifest" || die "unexpected $manifest"
	sudo sed -i '/^  path = "usr\/local\/bin\/attestation-agent"$/a\  env  = { LD_LIBRARY_PATH = "${extension_root}/usr/local/lib" }' "$manifest"
	ROOTFS_DIR=$root OUTPUT_DIR=$out/ext "$src/gc/tools/coco-extension/build-erofs-image.sh"
	sudo rm -rf "$root"
}

# Only the runtime-rs shim, the base guest image and the coco-dev config come
# from the pinned kata-static tarball; its QEMU is built without TPM support.
build_kata() {
	[[ -f $out/kata/containerd-shim-kata-v2 ]] && return
	info "extracting Kata $KATA_TAG"
	local tarball=$E2E_CACHE/kata-static-$KATA_TAG-amd64.tar.zst
	curl -fsSLo "$tarball" "https://github.com/kata-containers/kata-containers/releases/download/$KATA_TAG/kata-static-$KATA_TAG-amd64.tar.zst"
	echo "$KATA_STATIC_SHA256  $tarball" | sha256sum -c --quiet
	mkdir -p "$out/kata"
	tar --zstd -xf "$tarball" -C "$out/kata" --transform='s|.*/||' \
		./opt/kata/share/kata-containers/kata-ubuntu-resolute.image \
		./opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-coco-dev-runtime-rs.toml \
		./opt/kata/runtime-rs/bin/containerd-shim-kata-v2
	rm -f "$tarball"
}

kind() {
	local bin=$E2E_CACHE/bin/kind
	if [[ ! -x $bin ]]; then
		mkdir -p "${bin%/*}"
		curl -fsSLo "$bin.tmp" "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64"
		echo "$KIND_SHA256  $bin.tmp" | sha256sum -c --quiet
		chmod +x "$bin.tmp" && mv "$bin.tmp" "$bin"
	fi
	if [[ $ENGINE == podman ]]; then sudo KIND_EXPERIMENTAL_PROVIDER=podman "$bin" "$@"; else "$bin" "$@"; fi
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

# Expected PCR8 after the AA extends it once with the Init-Data digest.
pcr8_for() {
	python3 -c 'import hashlib,sys; d=hashlib.sha256(sys.stdin.buffer.read()).digest(); print(hashlib.sha256(bytes(32)+d).hexdigest())'
}

# run_probe <name> <initdata>: a pod that asks its CDH for $RESOURCE; prints
# what it got.
run_probe() {
	local name=$1 annotation
	annotation=$(printf '%s' "$2" | gzip -9 | b64)
	kc delete pod "$name" --ignore-not-found --wait >/dev/null
	kc apply -f - >/dev/null <<-EOF
		apiVersion: v1
		kind: Pod
		metadata:
		  name: $name
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
	build_kernel
	build_extension
	build_kata
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
	# Single steps, for debugging: build_kernel, build_aa, ...
	build_* | install_* | provision_*) "$1" ;;
	*) die "usage: $0 up|verify|down" ;;
	esac
}

main "$@"
