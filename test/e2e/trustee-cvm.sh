#!/usr/bin/env bash
# The Trustee CVM unlocks on the kind + Kata + swtpm cluster from
# kind-kata-swtpm.sh (run its `up` first), from deploy/examples.
#
#   image   the Bootstrap Helper image builds twice to the same digest
#   AT-25   Security Operators reach the helper through its Service while the
#   AT-13   pod is not Ready; two Shares of 2-of-3 unlock it and Trustee starts
#   AT-11   with another ceremony.json in the ConfigMap, the helper fails
#           in LOCKED under the same pod and policy
#   policy  genpolicy's agent policy denies exec, and a pod whose helper args
#           differ from the policy's does not start
#   state   the memory state volume is a guest tmpfs that the host never sees
#           and that survives the init-to-main handoff
#   AT-17   a workload that pins Trustee's certificate (kbs_cert) gets the
#   AT-24   sealed resource; one with other Init-Data is refused, so Trustee
#           runs the sealed policy and not its built-in default
#   AT-21   from the node's network, the host presents a self-signed token
#           naming its own TEE key, and gets nothing
#   AT-22   it calls the admin API without the admin key to replace the
#           resource policy, and is refused; AT-24 then shows the sealed
#           policy still rules
#   AT-26   the Trustee container restarts and serves again from the
#           published tree, with no new ceremony
#
# The helper image goes to a local registry on the kind gateway. The kind
# node pulls it over plain HTTP (containerd hosts.toml), and so does the
# guest: the test Init-Data adds an insecure-registry rule to cdh.toml.
#
# Needs: go, python3, openssl, curl, zstd, sudo and podman as the engine
# (E2E_ENGINE=podman), because the reproducible image build uses podman's
# --timestamp. Set E2E_WORK to keep the work directory.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=kind-kata-swtpm.sh
source "$script_dir/kind-kata-swtpm.sh"
info() { echo "[trustee-cvm] $*" >&2; }
die() { echo "[trustee-cvm] FAIL: $*" >&2; exit 1; }

# --- pins (docs/upstream-pins.md) -------------------------------------------
KATA_TOOLS_SHA256=a4f8e1b6ee500b6e94d3925249e741c75bb4a89bf275b5d5066d6275c68e29ef
REGISTRY_IMAGE=docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e

repo=$(cd "$script_dir/../.." && pwd)
examples=$repo/deploy/examples
work=${E2E_WORK:-$(mktemp -d)}
mkdir -p "$work"
GO=${GO:-go}
REGISTRY_NAME=$CLUSTER-registry
POD=trustee-cvm
HELPER_SVC=trustee-bootstrap-helper
# Trustee's certificate names a cluster-internal host only (spec §1).
TRUSTEE_HOST=trustee.default.svc.cluster.local
SECRET=default/e2e/secret
SECRET_VALUE=trustee-workload-ok

tb() { "$work/bin/trustee-bootstrap" "$@"; }

# delete_objects [--wait]: everything this test puts in the cluster.
delete_objects() {
	kc delete pod "$POD" tmpfs-probe workload-ok workload-other workload-again --ignore-not-found "${1:---wait=false}" >/dev/null 2>&1
	kc delete service "$HELPER_SVC" trustee --ignore-not-found >/dev/null 2>&1
	kc delete configmap trustee-ceremony-manifest trustee-sealed-bundle --ignore-not-found >/dev/null 2>&1
}

cleanup() {
	set +e
	delete_objects
	eng rm -f "$REGISTRY_NAME" >/dev/null 2>&1
	[[ -n ${E2E_WORK:-} ]] || rm -rf "$work"
}

# genpolicy, its rules and its settings, from the pinned Kata tools tarball.
# One settings drop-in: the kind node's containerd 2.3 writes OCI spec
# 1.3.0, and the stock settings expect 1.1.0, so the policy would refuse
# every container.
genpolicy_tool() {
	gp=$E2E_CACHE/out/genpolicy
	mkdir -p "$gp/genpolicy-settings.d"
	cp "$script_dir/genpolicy-kind.json" "$gp/genpolicy-settings.d/"
	[[ -x $gp/genpolicy ]] && return
	info "fetching genpolicy (Kata $KATA_TAG)"
	local tarball=$E2E_CACHE/kata-tools-static-$KATA_TAG-amd64.tar.zst
	curl -fsSLo "$tarball" "https://github.com/kata-containers/kata-containers/releases/download/$KATA_TAG/kata-tools-static-$KATA_TAG-amd64.tar.zst"
	echo "$KATA_TOOLS_SHA256  $tarball" | sha256sum -c --quiet
	mkdir -p "$gp"
	tar --zstd -xf "$tarball" -C "$gp" --transform='s|.*/||' ./opt/kata/bin/genpolicy \
		./opt/kata/share/defaults/kata-containers/rules.rego \
		./opt/kata/share/defaults/kata-containers/genpolicy-settings.json
	rm -f "$tarball"
}

# A registry on the kind gateway, which the node's containerd may use over
# plain HTTP.
registry_up() {
	registry=$gw:5000
	eng rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
	eng run -d --name "$REGISTRY_NAME" -p "$registry:5000" "$REGISTRY_IMAGE" >/dev/null
	node mkdir -p "/etc/containerd/certs.d/$registry"
	printf '[host."http://%s"]\n  capabilities = ["pull", "resolve"]\n' "$registry" |
		node dd status=none of="/etc/containerd/certs.d/$registry/hosts.toml"
	for _ in $(seq 30); do
		curl -fs -o /dev/null "http://$registry/v2/" && return
		sleep 1
	done
	die "the registry did not start"
}

# build_helper: build the Bootstrap Helper image twice from scratch and push
# both; the digests must match. Sets helper_image.
build_helper() {
	local digest=
	for build in 1 2; do
		eng build -q --no-cache --timestamp 0 --identity-label=false -f "$repo/cmd/bootstrap-helper/Containerfile" \
			-t "$registry/trustee-bootstrap/bootstrap-helper:$build" "$repo" >/dev/null
		eng push -q --tls-verify=false --digestfile "$work/digest-$build" "$registry/trustee-bootstrap/bootstrap-helper:$build"
		eng rmi "$registry/trustee-bootstrap/bootstrap-helper:$build" >/dev/null
		[[ -z $digest || $digest == "$(cat "$work/digest-$build")" ]] ||
			die "two builds of the helper image differ: $digest, $(cat "$work/digest-$build")"
		digest=$(cat "$work/digest-$build")
	done
	helper_image=$registry/trustee-bootstrap/bootstrap-helper@$digest
	info "image: two builds of the Bootstrap Helper image are both $digest"
}

# workload_initdata <extra line>: Init-Data for a workload that attests to
# the unlocked Trustee and trusts only Trustee's certificate on top of the
# system roots.
workload_initdata() {
	local cert
	cert=$(cat "$work/tree/tls.crt")
	cat <<-EOF
		version = "0.1.0"
		algorithm = "sha256"
		[data]
		"aa.toml" = '''
		[eventlog_config]
		init_pcr = 17
		enable_eventlog = false
		[token_configs.kbs]
		url = "https://$TRUSTEE_HOST:8080"
		cert = """
		$cert
		"""
		'''
		"cdh.toml" = '''
		socket = "unix:///run/confidential-containers/cdh.sock"
		credentials = []
		[kbc]
		name = "cc_kbc"
		url = "https://$TRUSTEE_HOST:8080"
		kbs_cert = """
		$cert
		"""
		'''
		$1
	EOF
}

# reference_value <name> <value>: the built-in RVPS's stored form.
reference_value() {
	printf '{"version":"0.1.0","name":"%s","expiration":"%s","value":["%s"]}' \
		"$1" "$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)" "$2" >"$work/tree/storage/reference_value/$1"
}

# The Infrastructure Operator's plaintext tree: the example config, fresh
# keys, the resource policy at KBS's exact key, one resource and the RVPS
# values that let the default AS policy mark swtpm evidence affirming.
trustee_tree() {
	local t=$work/tree
	mkdir -p "$t/storage/kbs" "$t/storage/repository" "$t/storage/reference_value"
	cp "$examples/trustee-config/kbs.toml" "$t/"
	# A self-signed leaf certificate: rustls refuses a CA certificate as the
	# server's own.
	openssl ecparam -name prime256v1 -genkey -noout -out "$t/tls.key"
	openssl req -new -key "$t/tls.key" -subj "/CN=$TRUSTEE_HOST" -out "$work/tls.csr"
	printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
		"$TRUSTEE_HOST" >"$work/tls.ext"
	openssl x509 -req -in "$work/tls.csr" -signkey "$t/tls.key" -days 2 -extfile "$work/tls.ext" -out "$t/tls.crt" 2>/dev/null
	openssl ecparam -name prime256v1 -genkey -noout -out "$t/as-signer.key"
	openssl req -x509 -new -key "$t/as-signer.key" -subj "/CN=Trustee AS signer" -days 2 -out "$t/as-signer.crt"
	# The admin key's private half is never kept.
	openssl genpkey -algorithm ed25519 | openssl pkey -pubout -out "$t/admin.pub"

	authorized=$(workload_initdata "")
	unauthorized=$(workload_initdata "# another workload")
	sed "s/@PCR8@/$(printf '%s' "$authorized" | pcr8_for)/" "$script_dir/resource-policy.rego" \
		>"$t/storage/kbs/resource-policy.rego"
	printf '%s' "$SECRET_VALUE" >"$t/storage/repository/${SECRET//\//\\x2F}"
	reference_value trusted_aks "$ak"
	reference_value tpm_pcr11 "$(printf '%064d' 0)"
}

# The Ceremony Authority splits 2-of-3; the Infrastructure Operator seals.
ceremony_and_seal() {
	mkdir -p "$work/bin" "$work/ceremony"
	CGO_ENABLED=0 "$GO" build -C "$repo" -o "$work/bin/" ./cmd/trustee-bootstrap
	CGO_ENABLED=0 "$GO" test -C "$repo" -c -o "$work/bin/attacker" ./test/e2e/attacker
	tb ceremony split --threshold 2 --holders alice,bob,carol --out-dir "$work/ceremony" >/dev/null
	trustee_tree
	bundle_sha256=$(tb seal --manifest "$work/ceremony/ceremony.json" --output "$work/bundle.age" "$work/tree")
}

# The example Init-Data plus a rule that lets the guest pull from the test
# registry over plain HTTP. cdh.toml is its last entry.
cvm_initdata() {
	python3 - "$examples/init-data.toml" "$registry" >"$work/init-data.toml" <<-'EOF'
		import sys
		s, r = open(sys.argv[1]).read(), sys.argv[2]
		head, sep, tail = s.rpartition("'''")
		rule = f'\n[image.registry_config]\n[[image.registry_config.registry]]\nprefix = "{r}"\nlocation = "{r}"\ninsecure = true\n'
		sys.stdout.write(head.rstrip("\n") + "\n" + rule + sep + tail)
	EOF
}

# The example pod with the helper image, then genpolicy. The Security
# Operators review init.toml: the Init-Data that genpolicy wrote, policy and
# all.
render_pod() {
	local manifest_sha256
	manifest_sha256=$(sha256sum "$work/ceremony/ceremony.json" | cut -d' ' -f1)
	sed "s|@HELPER_IMAGE@|$helper_image|; s|@MANIFEST_SHA256@|$manifest_sha256|" "$examples/trustee-cvm.yaml" >"$work/trustee-cvm.yaml"
	"$gp/genpolicy" -y "$work/trustee-cvm.yaml" -p "$gp/rules.rego" -j "$gp" \
		--initdata-path="$work/init-data.toml" --insecure-registry="$registry" >/dev/null
	python3 - "$work/trustee-cvm.yaml" >"$work/init.toml" <<-'EOF'
		import base64, gzip, re, sys
		m = re.search(r'cc_init_data: *"?([A-Za-z0-9+/=]+)', open(sys.argv[1]).read())
		sys.stdout.buffer.write(gzip.decompress(base64.b64decode(m.group(1))))
	EOF
	grep -q '"policy.rego"' "$work/init.toml" || die "genpolicy wrote no agent policy into the Init-Data"
}

# policy_build <holder>
policy_build() {
	tb policy build --init-data "$work/init.toml" --reference-values "$work/rv.json" --accept-tee tpm --allow-untested-profiles \
		--bundle-sha256 "$bundle_sha256" --manifest "$work/ceremony/ceremony.json" \
		--share-file "$work/ceremony/$1.share" --out-dir "$work/policy-$1" >/dev/null
}

# approve <holder>: prints "accepted", or the error output on failure. The
# audit records stay in $work/approve-<holder>.log.
approve() {
	tb approve --endpoint "$endpoint" --policy "$work/policy-$1" --share-file "$work/ceremony/$1.share" \
		2>"$work/approve-$1.log" || { cat "$work/approve-$1.log"; return 1; }
}

# status_is <state accepted>, e.g. status_is "COLLECTING [1]"
status_is() {
	local got
	got=$(tb status --endpoint "$endpoint" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["state"], s["accepted"])')
	[[ $got == "$1" ]] || die "status is '$got', want '$1'"
}

ready() { kc get pod "$POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'; }

# The pod's state volume as the host sees it.
host_state_dir() {
	echo "/var/lib/kubelet/pods/$(kc get pod "$1" -o jsonpath='{.metadata.uid}')/volumes/kubernetes.io~empty-dir/state"
}

deploy() {
	node mkdir -p /tmp/trustee-cvm
	eng cp "$work/ceremony/ceremony.json" "$CLUSTER-control-plane:/tmp/trustee-cvm/ceremony.json"
	eng cp "$work/bundle.age" "$CLUSTER-control-plane:/tmp/trustee-cvm/bundle.age"
	kc create configmap trustee-ceremony-manifest --from-file=/tmp/trustee-cvm/ceremony.json >/dev/null
	kc create configmap trustee-sealed-bundle --from-file=/tmp/trustee-cvm/bundle.age >/dev/null
	kc apply -f - <"$work/trustee-cvm.yaml" >/dev/null
	endpoint=http://$(kc get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'):$(
		kc get service "$HELPER_SVC" -o jsonpath='{.spec.ports[0].nodePort}')
}

wait_helper() {
	for _ in $(seq 150); do
		tb status --endpoint "$endpoint" >/dev/null 2>&1 && return
		sleep 2
	done
	die "the Bootstrap Helper did not answer: $(kc describe pod "$POD" | tail -10)"
}

unlock() {
	info "AT-25/AT-13: unlock through the helper's Service"
	deploy
	wait_helper
	[[ $(ready) == False ]] || die "the pod is Ready before the unlock"
	status_is "COLLECTING []"
	local out
	out=$(approve alice) || die "alice's approve: $out"
	[[ $out == accepted ]] || die "alice's approve printed '$out'"
	status_is "COLLECTING [1]"
	[[ $(ready) == False ]] || die "the pod is Ready with one Share of two"
	out=$(approve carol) || die "carol's approve: $out"
	[[ $out == accepted ]] || die "carol's approve printed '$out'"
	info "AT-25: both Security Operators reached the helper through $HELPER_SVC while the pod was not Ready"
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null ||
		die "Trustee did not start: $(kc describe pod "$POD" | tail -10)"
	info "AT-13: two Shares of 2-of-3 unlocked the Trustee CVM, and Trustee is Ready"
}

# The pod runs under the generated agent policy.
check_policy() {
	local out
	if out=$(kc exec "$POD" -c trustee -- /usr/local/bin/kbs --help 2>&1); then die "exec ran: $out"; fi
	[[ $out == *"ExecProcessRequest is blocked by policy"* ]] || die "exec failed, but not by policy: $out"
	info "policy: exec into the Trustee container is denied: ExecProcessRequest is blocked by policy"
}

# The tree the helper published is in the guest only.
check_host_view() {
	local dir entries
	dir=$(host_state_dir "$POD")
	entries=$(node ls -A "$dir") || die "no state volume on the host at $dir"
	[[ -z $entries ]] || die "the host sees the state volume's contents: $entries"
	info "state: the host's side of the state volume is empty while Trustee serves from it"
}

# A pod with the same volume layout and no policy, so it can report: the
# init container writes into the state volume, the main container reads it.
check_tmpfs() {
	kc apply -f - >/dev/null <<-EOF
		apiVersion: v1
		kind: Pod
		metadata:
		  name: tmpfs-probe
		spec:
		  runtimeClassName: $RUNTIME_CLASS
		  restartPolicy: Never
		  initContainers:
		  - name: init
		    image: $PROBE_IMAGE
		    command: ["sh", "-c", "echo handed-over >/state/marker"]
		    volumeMounts: [{name: state, mountPath: /state}]
		  containers:
		  - name: main
		    image: $PROBE_IMAGE
		    command: ["sh", "-c", "grep ' /state ' /proc/mounts; cat /state/marker; sleep 30"]
		    volumeMounts: [{name: state, mountPath: /state}]
		  volumes:
		  - name: state
		    emptyDir: {medium: Memory}
	EOF
	kc wait --for=condition=Ready pod/tmpfs-probe --timeout=300s >/dev/null || die "tmpfs-probe did not start"
	local out entries
	sleep 2
	out=$(kc logs tmpfs-probe -c main)
	entries=$(node ls -A "$(host_state_dir tmpfs-probe)")
	kc delete pod tmpfs-probe --wait=false >/dev/null
	[[ $out == *" /state tmpfs "*handed-over* ]] || die "state volume in the guest: $out"
	[[ -z $entries ]] || die "the host sees the probe's state volume: $entries"
	info "state: in the guest, the state volume is $(head -1 <<<"$out" | cut -d' ' -f1-3); the init container's file reached the main container; the host's side is empty"
}

# AT-21 and AT-22 against the unlocked Trustee, by the host from the node's
# network (test/e2e/attacker). The forged token carries the claims the
# sealed policy wants. check_workloads then shows that policy still rules.
check_host_attacks() {
	local url out
	url=https://$(kc get service trustee -o jsonpath='{.spec.clusterIP}'):8080
	eng cp "$work/bin/attacker" "$CLUSTER-control-plane:/tmp/attacker"
	for attack in forge admin; do
		out=$(node /tmp/attacker -test.run '^TestAttack$' -test.v -attack "$attack" -kbs "$url" -resource "$SECRET" \
			-pcr8 "$(printf '%s' "$authorized" | pcr8_for)" -ak "$ak" 2>&1) || die "$attack against Trustee: $out"
		[[ $out == *"HTTP "* ]] || die "$attack against Trustee: no answer: $out"
	done
	info "AT-21: Trustee refused a forged token naming the host's TEE key"
	info "AT-22: Trustee refused resource policy replacements without the admin key"
}

# Workload Attestation against the unlocked Trustee.
check_workloads() {
	local got
	RESOURCE=$SECRET
	got=$(run_probe workload-ok "$authorized")
	[[ $got == "$SECRET_VALUE" ]] || die "authorized workload got '$got'"
	info "AT-17: a workload that pins Trustee's certificate attested and got the sealed resource"
	got=$(run_probe workload-other "$unauthorized")
	[[ $got == DENIED ]] || die "unauthorized workload got '$got'"
	kc delete pod workload-ok workload-other --wait=false >/dev/null
	info "AT-24: a workload with other Init-Data was refused: the sealed policy rules, not KBS's default"
}

# AT-26: the KBS container dies and kubelet restarts it in the same sandbox.
# The helper does not run again, and Trustee serves from the tree it
# published, with no new Unlock Ceremony.
check_trustee_restart() {
	local id helper_runs restarts got
	id=$(kc get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}')
	helper_runs=$(kc get pod "$POD" -o jsonpath='{.status.initContainerStatuses[0].restartCount}')
	node crictl stop "${id#containerd://}" >/dev/null || die "could not stop the Trustee container"
	for _ in $(seq 90); do
		restarts=$(kc get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')
		[[ $restarts -ge 1 && $(ready) == True ]] && break
		sleep 2
	done
	[[ $restarts -ge 1 && $(ready) == True ]] ||
		die "Trustee did not come back: $(kc describe pod "$POD" | tail -10)"
	[[ $(kc get pod "$POD" -o jsonpath='{.status.initContainerStatuses[0].restartCount}') == "$helper_runs" ]] ||
		die "the helper ran again after the Trustee container restarted"
	RESOURCE=$SECRET
	got=$(run_probe workload-again "$authorized")
	[[ $got == "$SECRET_VALUE" ]] || die "after the Trustee restart, the workload got '$got'"
	kc delete pod workload-again --wait=false >/dev/null
	info "AT-26: the Trustee container restarted and served the sealed resource from the published tree, with no new ceremony"
}

# The same pod and policy, with one helper arg changed.
check_tampered() {
	kc delete pod "$POD" --ignore-not-found --wait >/dev/null
	sed 's|--proxy-port=8081|--proxy-port=8082|' "$work/trustee-cvm.yaml" | kc apply -f - >/dev/null
	local events='' uid
	uid=$(kc get pod "$POD" -o jsonpath='{.metadata.uid}')
	for _ in $(seq 90); do
		events=$(kc get events --field-selector "involvedObject.uid=$uid" -o jsonpath='{.items[*].message}')
		[[ $events == *CreateContainerRequest* ]] && break
		sleep 2
	done
	# The refused request is the helper's, with the changed arg.
	[[ $events == *"CreateContainerRequest is blocked by policy"*--proxy-port=8082* ]] ||
		die "a changed helper arg was not refused: ${events:0:2000}"
	[[ -z $(kc get pod "$POD" -o jsonpath='{.status.initContainerStatuses[0].state.running}') ]] ||
		die "the helper runs with a changed arg"
	kc delete pod "$POD" --wait=false >/dev/null
	info "policy: with --proxy-port changed, the agent refused to create the helper container"
}

# The same pod and policy, with another Key Ceremony's ceremony.json in the
# manifest ConfigMap. The policy can't pin ConfigMap contents, so the helper
# starts, and --manifest-sha256 makes it fail in LOCKED.
check_swapped_manifest() {
	kc delete pod "$POD" --ignore-not-found --wait >/dev/null
	mkdir -p "$work/other"
	tb ceremony split --threshold 2 --holders x,y --out-dir "$work/other" >/dev/null
	eng cp "$work/other/ceremony.json" "$CLUSTER-control-plane:/tmp/trustee-cvm/other.json"
	kc delete configmap trustee-ceremony-manifest >/dev/null
	kc create configmap trustee-ceremony-manifest --from-file=ceremony.json=/tmp/trustee-cvm/other.json >/dev/null
	kc apply -f - <"$work/trustee-cvm.yaml" >/dev/null
	# The helper's exit code, now or before its last restart.
	local codes='' exit1='(^| )1( |$)'
	for _ in $(seq 150); do
		codes=$(kc get pod "$POD" -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode} {.status.initContainerStatuses[0].lastState.terminated.exitCode}') || true
		[[ $codes =~ $exit1 ]] && break
		sleep 2
	done
	[[ $codes =~ $exit1 ]] || die "the helper did not fail with a swapped manifest: exit codes '$codes'; $(kc describe pod "$POD" | tail -10)"
	tb status --endpoint "$endpoint" >/dev/null 2>&1 && die "the helper serves with a swapped manifest"
	kc delete pod "$POD" --wait=false >/dev/null
	info "AT-11: with another ceremony.json in the ConfigMap, the helper exited 1 in LOCKED"
}

main() {
	trap cleanup EXIT
	delete_objects --wait || true
	gw=$(node ip -4 route show default | awk '{print $3}')
	ak=$(node sed '/-----/d' /opt/kata-swtpm/ak.pem | tr -d '\n')
	printf '{"trusted_aks":["%s"],"tpm_pcr11":["%064d"]}' "$ak" 0 >"$work/rv.json"
	genpolicy_tool
	registry_up
	build_helper
	ceremony_and_seal
	cvm_initdata
	render_pod
	policy_build alice
	policy_build carol

	unlock
	check_policy
	check_host_view
	check_host_attacks
	check_workloads
	check_trustee_restart
	check_tampered
	check_swapped_manifest
	check_tmpfs
	info "PASS"
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
