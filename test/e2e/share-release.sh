#!/usr/bin/env bash
# A Share released over real attestation, on the kind + Kata + swtpm cluster
# from kind-kata-swtpm.sh (run its `up` first).
#
#   AT-03  matching Init-Data: two Security Operators approve; the pod's
#          stock CDH gets each Share payload through the guest proxy, the
#          relay and the Operator Verifier, and the Bootstrap Helper publishes
#   AT-04  changed Init-Data: the Operator Verifier releases nothing
#   AT-06  a capture of all relay traffic, inner and outer, holds no Share
#
# The Bootstrap Helper runs as a plain process in a busybox Kata pod, reached
# through a NodePort. Its binary, the Ceremony Manifest and the Sealed Bundle
# are fetched from a file server on the kind gateway; ticket 06 replaces this
# with the real Trustee CVM pod. alice's Operator Verifier is the pinned KBS
# image. carol's uses --kbs-binary with a wrapper that runs the image's kbs in
# the host network namespace, because the image's kbs needs Intel DCAP
# libraries that a stock host lacks.
#
# Needs: go, python3, tcpdump, sudo, podman or docker. Set E2E_WORK to keep
# the work directory.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=kind-kata-swtpm.sh
source "$script_dir/kind-kata-swtpm.sh"
info() { echo "[share-release] $*" >&2; }
die() { echo "[share-release] FAIL: $*" >&2; exit 1; }

repo=$(cd "$script_dir/../.." && pwd)
work=${E2E_WORK:-$(mktemp -d)}
GO=${GO:-go}
FILES_PORT=8099
NODE_PORT=30080
HELPER=bootstrap-helper
# The engine the CLI picks (verifier.DefaultEngine).
CLI_ENGINE=$(command -v podman >/dev/null && echo podman || echo docker)

tb() { "$work/bin/trustee-bootstrap" "$@"; }

cleanup() {
	set +e
	[[ -z ${capture_pid:-} ]] || sudo kill -INT "$capture_pid"
	[[ -z ${files_pid:-} ]] || kill "$files_pid"
	kc delete pod,service "$HELPER" --ignore-not-found --wait=false >/dev/null 2>&1
	[[ -n ${E2E_WORK:-} ]] || sudo rm -rf "$work"
}
trap cleanup EXIT

# The Ceremony Authority splits 2-of-3; the Infrastructure Operator seals a
# one-file tree.
setup() {
	mkdir -p "$work/bin" "$work/files" "$work/tree" "$work/ceremony"
	CGO_ENABLED=0 "$GO" build -C "$repo" -o "$work/bin/" ./cmd/trustee-bootstrap ./cmd/bootstrap-helper
	tb ceremony split --threshold 2 --holders alice,bob,carol --out-dir "$work/ceremony" >/dev/null
	echo 'package policy' >"$work/tree/resource.rego"
	bundle_sha256=$(tb seal --manifest "$work/ceremony/ceremony.json" --output "$work/files/bundle.age" "$work/tree")
	cp "$work/ceremony/ceremony.json" "$work/bin/bootstrap-helper" "$work/files/"

	cat >"$work/bin/kbs" <<-EOF
		#!/bin/sh
		dir=\$(dirname "\$2")
		exec $CLI_ENGINE run --rm --network host -v "\$dir:\$dir:Z" $KBS_IMAGE /usr/local/bin/kbs "\$@"
	EOF
	chmod +x "$work/bin/kbs"
}

# policy_build <holder>: the Security Operator reviews init.toml and builds
# their Operator Policy from it.
policy_build() {
	tb policy build --init-data "$work/init.toml" --reference-values "$work/rv.json" --accept-tee tpm \
		--bundle-sha256 "$bundle_sha256" --manifest "$work/ceremony/ceremony.json" \
		--share-file "$work/ceremony/$1.share" --out-dir "$work/policy-$1" >/dev/null
}

# helper_pod <initdata>: (re)start the Bootstrap Helper in a Kata pod with
# that Init-Data, and wait until its status answers.
helper_pod() {
	local annotation
	annotation=$(printf '%s' "$1" | gzip -9 | b64)
	kc delete pod "$HELPER" --ignore-not-found --wait >/dev/null
	kc apply -f - >/dev/null <<-EOF
		apiVersion: v1
		kind: Pod
		metadata:
		  name: $HELPER
		  labels: {app: $HELPER}
		  annotations:
		    io.katacontainers.config.hypervisor.cc_init_data: "$annotation"
		spec:
		  runtimeClassName: $RUNTIME_CLASS
		  restartPolicy: Never
		  containers:
		  - name: helper
		    image: $PROBE_IMAGE
		    command: ["sh", "-euc", "cd /tmp && for f in bootstrap-helper ceremony.json bundle.age; do wget -q http://$gw:$FILES_PORT/\$f; done && chmod +x bootstrap-helper && exec ./bootstrap-helper --manifest ceremony.json --bundle bundle.age --out /tmp/trustee --listen :8080 --proxy-port 8081"]
		---
		apiVersion: v1
		kind: Service
		metadata:
		  name: $HELPER
		spec:
		  type: NodePort
		  selector: {app: $HELPER}
		  publishNotReadyAddresses: true
		  ports: [{port: 8080, targetPort: 8080, nodePort: $NODE_PORT}]
	EOF
	for _ in $(seq 150); do
		tb status --endpoint "$endpoint" >/dev/null 2>&1 && return
		sleep 2
	done
	die "the Bootstrap Helper did not start: $(kc describe pod "$HELPER" | tail -5; kc logs "$HELPER" 2>&1 | tail -5)"
}

# status_is <state accepted>, e.g. status_is "PUBLISHED [1, 3]"
status_is() {
	local got
	got=$(tb status --endpoint "$endpoint" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["state"], s["accepted"])')
	[[ $got == "$1" ]] || die "status is '$got', want '$1'"
}

# approve <holder> [flags...]
approve() {
	local holder=$1
	shift
	tb approve --endpoint "$endpoint" --policy "$work/policy-$holder" \
		--share-file "$work/ceremony/$holder.share" "$@" 2>&1
}

# assert_no_share <pcap>: no Share, raw or base64, appears in the capture,
# and the capture did see the relay, RCAR and the JWE.
assert_no_share() {
	python3 - "$1" "$work"/ceremony/*.share <<-'EOF'
		import base64, json, sys
		cap = open(sys.argv[1], "rb").read()
		for path in sys.argv[2:]:
		    share = base64.b64decode(json.load(open(path))["share"])
		    for needle in (share, base64.b64encode(share), base64.urlsafe_b64encode(share).rstrip(b"=")):
		        if needle in cap:
		            sys.exit(f"Share bytes from {path} in the relay capture")
		for marker in (b"/bootstrap/v1/relay", b"/kbs/v0/attest", b'"ciphertext"'):
		    if marker not in cap:
		        sys.exit(f"the capture lacks {marker!r}, so it missed the exchange")
	EOF
}

main() {
	gw=$(node ip -4 route show default | awk '{print $3}')
	endpoint=http://$(kc get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'):$NODE_PORT
	setup
	local good bad ak out
	good=$(initdata "http://127.0.0.1:8081" "")
	bad=$(initdata "http://127.0.0.1:8081" "# changed")
	printf '%s' "$good" >"$work/init.toml"
	ak=$(node sed '/-----/d' /opt/kata-swtpm/ak.pem | tr -d '\n')
	printf '{"trusted_aks":["%s"],"tpm_pcr11":["%064d"]}' "$ak" 0 >"$work/rv.json"
	policy_build alice
	policy_build carol
	python3 -m http.server "$FILES_PORT" --bind "$gw" --directory "$work/files" >/dev/null 2>&1 &
	files_pid=$!

	info "AT-03: matching Init-Data"
	helper_pod "$good"
	status_is "COLLECTING []"
	# Everything but ssh: the relay WebSocket and, on loopback, the bytes it
	# carries between the CLI and the Operator Verifier.
	sudo tcpdump -i any -U -s 0 -Z root -w "$work/relay.pcap" 'tcp and not port 22' 2>/dev/null &
	capture_pid=$!
	sleep 2
	out=$(approve alice) || die "alice's approve: $out"
	[[ $out == accepted ]] || die "alice's approve printed '$out'"
	status_is "COLLECTING [1]"
	out=$(approve carol --kbs-binary "$work/bin/kbs") || die "carol's approve: $out"
	[[ $out == accepted ]] || die "carol's approve printed '$out'"
	# The helper exits 0 only after it published the tree.
	kc wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$HELPER" --timeout=60s >/dev/null ||
		die "the Bootstrap Helper did not publish: $(kc logs "$HELPER" 2>&1 | tail -5)"
	info "AT-03: both Shares released and accepted; the Bootstrap Helper published and exited 0"

	sleep 1
	sudo kill -INT "$capture_pid"
	wait "$capture_pid" || true
	capture_pid=
	assert_no_share "$work/relay.pcap" || die "AT-06"
	info "AT-06: the relay capture ($(stat -c %s "$work/relay.pcap") bytes) holds no Share"

	info "AT-04: changed Init-Data"
	helper_pod "$bad"
	if out=$(approve alice); then die "changed Init-Data: Share released: $out"; fi
	[[ $out == *"not accepted"* ]] || die "changed Init-Data: approve failed for another reason: $out"
	status_is "COLLECTING []"
	info "AT-04: the Operator Verifier released nothing"
	info "PASS"
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
