#!/usr/bin/env bash
# A Share released over real attestation, on the kind + Kata + swtpm cluster
# from kind-kata-swtpm.sh (run its `up` first).
#
#   AT-03  matching Init-Data: two Security Operators approve; the pod's
#          stock CDH gets each Share payload through the guest proxy, the
#          relay and the Operator Verifier, and the Bootstrap Helper publishes
#   AT-04  changed Init-Data: the Operator Verifier releases nothing
#   AT-06  a capture of all relay traffic, inner and outer, holds no Share,
#          and neither do the audit records of approve and the helper
#   AT-18  after every approve (success, failure, SIGINT, SIGTERM, and with
#          a rootful engine), no Operator Verifier container, run directory
#          or listener remains
#   AT-02  while approve runs, its only new listener is on 127.0.0.1
#
# A relay holder (test/e2e/attacker) poses as the Bootstrap Helper and
# attacks through the relay that approve opens to it:
#
#   AT-21  a self-signed token naming the attacker's TEE key: no release
#   AT-22  replacing the resource policy without the admin key: refused,
#          and the Operator Verifier's policy file is unchanged
#   AT-05  relaying the genuine CVM's attestation with the attacker's TEE
#          key, or with evidence recorded from an earlier run: no release.
#          The control run, relayed untouched, does get a release.
#
# The Bootstrap Helper runs as a plain process in a busybox Kata pod, reached
# through a NodePort. Its binary, the Ceremony Manifest and the Sealed Bundle
# are fetched from a file server on the kind gateway. trustee-cvm.sh runs the
# real Trustee CVM pod instead. alice's Operator Verifier is the pinned KBS
# image. carol's uses --kbs-binary with a wrapper that runs the image's kbs in
# the host network namespace, because the image's kbs needs Intel DCAP
# libraries that a stock host lacks.
#
# Needs: go, python3, tcpdump, ss, sudo, podman or docker. Set E2E_WORK to
# keep the work directory.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=kind-kata-swtpm.sh
source "$script_dir/kind-kata-swtpm.sh"
# shellcheck source=operators.sh
source "$script_dir/operators.sh"
info() { echo "[share-release] $*" >&2; }
die() { echo "[share-release] FAIL: $*" >&2; exit 1; }

repo=$(cd "$script_dir/../.." && pwd)
work=${E2E_WORK:-$(mktemp -d)}
GO=${GO:-go}
FILES_PORT=8099
NODE_PORT=30080
HELPER=bootstrap-helper
# Where the relay holder poses as the Bootstrap Helper.
ATTACKER=127.0.0.1:8098
# The engine the CLI picks (verifier.DefaultEngine).
CLI_ENGINE=$(command -v podman >/dev/null && echo podman || echo docker)

cleanup() {
	set +e
	[[ -z ${attacker_pid:-} ]] || kill "$attacker_pid"
	[[ -z ${capture_pid:-} ]] || sudo kill -INT "$capture_pid"
	[[ -z ${files_pid:-} ]] || kill "$files_pid"
	kc delete pod,service "$HELPER" --ignore-not-found --wait=false >/dev/null 2>&1
	[[ -n ${E2E_WORK:-} ]] || sudo rm -rf "$work"
}
trap cleanup EXIT

# The Ceremony Authority splits 2-of-3; the Infrastructure Operator seals a
# minimal tree that passes the sealed-config checks where the helper below
# publishes it (/tmp/trustee). No KBS runs on it, so the signer files are
# placeholders.
setup() {
	mkdir -p "$work/bin" "$work/files" "$work/tree/storage/kbs" "$work/ceremony"
	CGO_ENABLED=0 "$GO" build -C "$repo" -o "$work/bin/" ./cmd/trustee-bootstrap ./cmd/bootstrap-helper
	CGO_ENABLED=0 "$GO" test -C "$repo" -c -o "$work/bin/attacker" ./test/e2e/attacker
	tb ceremony split --threshold 2 --holders alice,bob,carol --out-dir "$work/ceremony" >/dev/null
	sed 's#/trustee/config#/tmp/trustee#' "$repo/deploy/examples/trustee-config/kbs.toml" >"$work/tree/kbs.toml"
	echo placeholder >"$work/tree/as-signer.key"
	echo placeholder >"$work/tree/as-signer.crt"
	tls_pair "$work/tree" trustee.default.svc.cluster.local
	printf 'package policy\n\ndefault allow := false\n' >"$work/tree/storage/kbs/resource-policy.rego"
	bundle_sha256=$(tb seal --manifest "$work/ceremony/ceremony.json" --output "$work/files/bundle.age" \
		--root /tmp/trustee "$work/tree")
	manifest_sha256=$(sha256sum "$work/ceremony/ceremony.json" | cut -d" " -f1)
	cp "$work/ceremony/ceremony.json" "$work/bin/bootstrap-helper" "$work/files/"

	cat >"$work/bin/kbs" <<-EOF
		#!/bin/sh
		dir=\$(dirname "\$2")
		exec $CLI_ENGINE run --rm --network host -v "\$dir:\$dir:Z" $KBS_IMAGE /usr/local/bin/kbs "\$@"
	EOF
	chmod +x "$work/bin/kbs"

	# A rootful engine: the KBS container runs as host root.
	mkdir -p "$work/rootful"
	if [[ $CLI_ENGINE == podman ]]; then
		printf '#!/bin/sh\nexec sudo env -u XDG_RUNTIME_DIR %s "$@"\n' "$(command -v podman)" >"$work/rootful/podman"
		chmod +x "$work/rootful/podman"
	fi
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
		    command: ["sh", "-euc", "cd /tmp && for f in bootstrap-helper ceremony.json bundle.age; do wget -q http://$gw:$FILES_PORT/\$f; done && chmod +x bootstrap-helper && exec ./bootstrap-helper --manifest ceremony.json --manifest-sha256 $manifest_sha256 --bundle bundle.age --out /tmp/trustee --owner-uid 0 --owner-gid 0 --listen :8080 --proxy-port 8081"]
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

# TCP listeners on this machine, less the test's own attacker, which comes
# and goes with each attack.
listeners() { ss -Hltn | awk -v a="$ATTACKER" '$4 != a {print $4}' | sort -u; }

# assert_clean <case>: AT-18, after approve exited. Compares listeners with
# $baseline, taken before approve started.
assert_clean() {
	local images left
	images=$({ "$CLI_ENGINE" ps -a --format '{{.Image}}'; eng ps -a --format '{{.Image}}'; } 2>/dev/null)
	[[ $images != *key-broker-service* ]] || die "AT-18 ($1): an Operator Verifier container remains"
	left=$(compgen -G "${XDG_RUNTIME_DIR:-/dev/shm}/trustee-bootstrap-verifier-*" || true)
	[[ -z $left ]] || die "AT-18 ($1): run directory left: $(ls -lR "$left")"
	[[ $(listeners) == "$baseline" ]] || die "AT-18 ($1): listeners changed: $(diff <(echo "$baseline") <(listeners))"
}

# attacker <attack> [flags...]: start the relay holder, posing as the
# Bootstrap Helper at $ATTACKER, and take the listener baseline.
attacker() {
	local attack=$1
	shift
	attacker_log=$work/attacker-$attack.log
	"$work/bin/attacker" -test.run '^TestAttack$' -test.v -attack "$attack" -listen "$ATTACKER" \
		-helper "$endpoint" "$@" >"$attacker_log" 2>&1 &
	attacker_pid=$!
	for _ in $(seq 50); do
		if tb status --endpoint "http://$ATTACKER" >/dev/null 2>&1; then
			baseline=$(listeners)
			return
		fi
		sleep 0.2
	done
	die "the attacker did not start: $(cat "$attacker_log")"
}

# attacker_passed <case>: the attacker exits 0 when its target held.
attacker_passed() {
	wait "$attacker_pid" || die "$1: $(cat "$attacker_log")"
	attacker_pid=
}

# signal_approve <signal>: AT-02 while approve holds a relay open to a
# relay holder that never attests, then AT-18 after the signal.
signal_approve() {
	local pid new
	attacker hold
	# The binary itself, so the signal reaches approve and not a subshell.
	"$work/bin/trustee-bootstrap" approve --endpoint "http://$ATTACKER" --policy "$work/policy-alice" \
		--share-file "$work/ceremony/alice.share" >"$work/approve-$1.log" 2>&1 &
	pid=$!
	for _ in $(seq 150); do
		grep -q "relay open" "$attacker_log" && break
		sleep 0.2
	done
	grep -q "relay open" "$attacker_log" || die "approve did not open the relay: $(cat "$work/approve-$1.log")"
	new=$(comm -13 <(echo "$baseline") <(listeners))
	[[ -n $new ]] || die "AT-02: approve runs with no new listener, so the check saw nothing"
	if grep -v '^127\.0\.0\.1:' <<<"$new"; then die "AT-02: approve listens beyond 127.0.0.1"; fi
	info "AT-02: while approve runs, its only new listener is $(tr '\n' ' ' <<<"$new")"
	kill -"$1" "$pid"
	if wait "$pid"; then die "approve exited 0 after SIG$1"; fi
	attacker_passed "hold"
	assert_clean "SIG$1"
	info "AT-18: after SIG$1, nothing of the Operator Verifier remains"
}

# relay_attacks: AT-21, AT-22 and AT-05 by a relay holder, against a helper
# pod with the matching Init-Data. Ends with alice's Share accepted.
relay_attacks() {
	local out rootful_path=$PATH
	[[ $CLI_ENGINE != podman ]] || rootful_path=$work/rootful:$PATH

	attacker forge -pcr8 "$(pcr8_for <"$work/init.toml")" -ak "$ak"
	if out=$(approve_via "http://$ATTACKER" alice); then die "AT-21: approve succeeded: $out"; fi
	attacker_passed "AT-21"
	assert_clean "forged token"
	info "AT-21: the Operator Verifier refused a forged token: $(grep -o 'forged token: HTTP [0-9]*' "$attacker_log")"

	# With a rootful engine, KBS writes its AS policies as root.
	attacker admin -policy-unchanged "$work/policy-alice/resource-policy.rego"
	if out=$(PATH=$rootful_path approve_via "http://$ATTACKER" alice); then die "AT-22: approve succeeded: $out"; fi
	attacker_passed "AT-22"
	assert_clean "admin call, rootful engine"
	info "AT-22: the Operator Verifier refused both resource policy replacements, and its policy is unchanged"
	info "AT-18: with a rootful engine, nothing of the Operator Verifier remains"

	attacker pass -evidence "$work/evidence.json"
	out=$(approve_via "http://$ATTACKER" alice) || die "AT-05 control: alice's approve through the untouched relay: $out"
	[[ $out == accepted ]] || die "AT-05 control: alice's approve printed '$out'"
	attacker_passed "AT-05 control"
	status_is "COLLECTING [1]"
	info "AT-05 control: relayed untouched by the relay holder, the genuine CVM got alice's Share"

	for attack in tee-pubkey replay; do
		attacker "$attack" -evidence "$work/evidence.json"
		if out=$(approve_via "http://$ATTACKER" carol); then die "AT-05 $attack: Share released: $out"; fi
		[[ $out == *"not accepted"* ]] || die "AT-05 $attack: approve failed for another reason: $out"
		attacker_passed "AT-05 $attack"
		assert_clean "AT-05 $attack"
		status_is "COLLECTING [1]"
	done
	info "AT-05: with the attacker's TEE key, or with replayed evidence, the Operator Verifier released nothing"
}

# assert_no_share <pcap> <audit log>: no Share, raw, hex or base64, appears
# in the capture or the audit records. The capture did see the relay, RCAR
# and the JWE, and the audit log holds both sides' records.
assert_no_share() {
	python3 - "$1" "$2" "$work"/ceremony/*.share <<-'EOF'
		import base64, json, sys
		cap, audit = (open(p, "rb").read() for p in sys.argv[1:3])
		for path in sys.argv[3:]:
		    share = base64.b64decode(json.load(open(path))["share"])
		    for needle in (share, share.hex().encode(), base64.b64encode(share).rstrip(b"="),
		                   base64.urlsafe_b64encode(share).rstrip(b"=")):
		        for name, data in (("relay capture", cap), ("audit log", audit)):
		            if needle in data:
		                sys.exit(f"Share bytes from {path} in the {name}")
		for marker in (b"/bootstrap/v1/relay", b"/kbs/v0/attest", b'"ciphertext"'):
		    if marker not in cap:
		        sys.exit(f"the capture lacks {marker!r}, so it missed the exchange")
		for event in (b'"msg":"approve_result"', b'"msg":"share_accepted"', b'"state":"PUBLISHED"'):
		    if event not in audit:
		        sys.exit(f"the audit log lacks {event!r}")
	EOF
}

main() {
	gw=$(node ip -4 route show default | awk '{print $3}')
	endpoint=http://$(kc get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'):$NODE_PORT
	setup
	local good bad out
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
	baseline=$(listeners)
	out=$(approve alice) || die "alice's approve: $out"
	[[ $out == accepted ]] || die "alice's approve printed '$out'"
	assert_clean "accepted"
	status_is "COLLECTING [1]"
	out=$(approve carol --kbs-binary "$work/bin/kbs") || die "carol's approve: $out"
	[[ $out == accepted ]] || die "carol's approve printed '$out'"
	assert_clean "accepted, --kbs-binary"
	# The helper exits 0 only after it published the tree.
	kc wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$HELPER" --timeout=60s >/dev/null ||
		die "the Bootstrap Helper did not publish: $(kc logs "$HELPER" 2>&1 | tail -5)"
	info "AT-03: both Shares released and accepted; the Bootstrap Helper published and exited 0"
	kc logs "$HELPER" >>"$work/audit.log"

	sleep 1
	sudo kill -INT "$capture_pid"
	wait "$capture_pid" || true
	capture_pid=
	assert_no_share "$work/relay.pcap" "$work/audit.log" || die "AT-06"
	info "AT-06: the relay capture ($(stat -c %s "$work/relay.pcap") bytes) and the audit log ($(wc -l <"$work/audit.log") records) hold no Share"

	info "relay holder attacks"
	helper_pod "$good"
	signal_approve INT
	signal_approve TERM
	relay_attacks

	info "AT-04: changed Init-Data"
	helper_pod "$bad"
	baseline=$(listeners)
	if out=$(approve alice); then die "changed Init-Data: Share released: $out"; fi
	[[ $out == *"not accepted"* ]] || die "changed Init-Data: approve failed for another reason: $out"
	assert_clean "not accepted"
	status_is "COLLECTING []"
	info "AT-04: the Operator Verifier released nothing"
	info "AT-18: after success and after failure, nothing of the Operator Verifier remains"
	info "PASS"
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
