#!/usr/bin/env bash
# More negative evals (docs/evals) on the kind + Kata + swtpm cluster from
# kind-kata-swtpm.sh (run its `up` first). evals.sh holds EV-01, EV-11 and
# EV-15; this script holds the rest that need the cluster:
#
#   ev02   the host splices one approve run into several CVMs
#   ev03   the host ignores a withdrawal and forges the status
#   ev04   an impostor KBS behind Trustee's Service gets no workload
#   ev05   the review checklist catches a weakened Init-Data
#   ev06   each failure the Unlock Ceremony runbook names shows its text
#   ev09   a helper upgrade, its faults, the rollback and a config upgrade
#   ev10   after a roster change, a departed operator's old Share is useless
#   ev12   approve killed with SIGKILL leaves nothing behind
#   ev13   a relay the host cuts mid-run is safe to retry
#   ev14   a syntactically broken sealed resource policy releases nothing
#
#   evals-cluster.sh [ev02 ... ev14]   run the named evals, or all of them
#
# One setup serves every eval. Each eval runs in its own subshell, so one
# failure doesn't stop the others; the summary names every failed eval.
# Needs what trustee-cvm.sh needs. Set E2E_WORK to choose the work directory.
# shellcheck disable=SC2030,SC2031 # subshells override work, SECRET_VALUE and others on purpose
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=evals.sh
source "$script_dir/evals.sh"
info() { echo "[evals-cluster] $*" >&2; }
die() { echo "[evals-cluster] FAIL: $*" >&2; exit 1; }

# set_manifest <file>: the host puts <file> in the Ceremony Manifest ConfigMap.
set_manifest() {
	kc create configmap trustee-ceremony-manifest --from-file=ceremony.json=/dev/stdin --dry-run=client -o yaml <"$1" |
		kc apply -f - >/dev/null 2>&1
}

# baseline: the setup's manifest and bundle in their ConfigMaps, whatever
# an earlier eval left there.
baseline() {
	set_manifest "$work/ceremony/ceremony.json"
	set_bundle "$work/bundle.age"
}

# blocked_by_policy: the agent refused to create a container in the
# current trustee-cvm pod; prints the request it named.
blocked_by_policy() {
	local uid events=''
	uid=$(pod "$POD" '{.metadata.uid}')
	for _ in $(seq 90); do
		events=$(kc get events --field-selector "involvedObject.uid=$uid" -o jsonpath='{.items[*].message}')
		[[ $events == *"is blocked by policy"* ]] && break
		sleep 2
	done
	grep -o '[A-Za-z]*Request is blocked by policy' <<<"$events" | head -1
}

# EV-04: the host runs its own KBS, with a fresh certificate for Trustee's
# host name, and points Trustee's Service at it.
ev04() {
	section "EV-04: Impostor Trustee serves workloads"
	local imp=$work/impostor value got
	value=IMPOSTOR-$(openssl rand -hex 8)
	baseline
	fresh_pod
	unlock_pod
	RESOURCE=$SECRET
	[[ $(run_probe workload-ok "$authorized") == "$SECRET_VALUE" ]] || die "EV-04: the workload got nothing from the real Trustee"

	# The host's tree: its own TLS pair and AS signer, a policy that
	# releases everything, and its own value at the workload's path.
	mkdir -p "$imp"
	cp -r "$work/tree/." "$imp/"
	tls_pair "$imp" "$TRUSTEE_HOST"
	openssl ecparam -name prime256v1 -genkey -noout -out "$imp/as-signer.key"
	openssl req -x509 -new -key "$imp/as-signer.key" -subj "/CN=host AS signer" -days 2 -out "$imp/as-signer.crt"
	printf 'package policy\n\ndefault allow := true\n' >"$imp/storage/kbs/resource-policy.rego"
	printf '%s' "$value" >"$imp/storage/repository/${SECRET//\//\\x2F}"
	tar -C "$imp" -cf "$work/impostor.tar" .
	trap 'kc patch service trustee --type merge -p "{\"spec\":{\"selector\":{\"app\":\"trustee-cvm\"}}}" >/dev/null 2>&1
		kc delete pod impostor workload-imp workload-ok workload-again --ignore-not-found --wait=false >/dev/null 2>&1
		kc delete configmap impostor-tree --ignore-not-found >/dev/null 2>&1' EXIT
	kc delete configmap impostor-tree --ignore-not-found >/dev/null
	kc create configmap impostor-tree --from-file=tree.tar=/dev/stdin <"$work/impostor.tar" >/dev/null
	kc apply -f - >/dev/null <<-EOF
		apiVersion: v1
		kind: Pod
		metadata:
		  name: impostor
		  labels: {app: impostor}
		spec:
		  initContainers:
		  - name: unpack
		    image: $PROBE_IMAGE
		    command: ["tar", "-xf", "/cm/tree.tar", "-C", "/trustee/config"]
		    volumeMounts: [{name: tree, mountPath: /cm}, {name: state, mountPath: /trustee/config}]
		  containers:
		  - name: kbs
		    image: $KBS_IMAGE
		    command: ["/usr/local/bin/kbs", "--config-file", "/trustee/config/kbs.toml"]
		    ports: [{containerPort: 8080}]
		    readinessProbe: {tcpSocket: {port: 8080}}
		    volumeMounts: [{name: state, mountPath: /trustee/config}]
		  volumes:
		  - name: tree
		    configMap: {name: impostor-tree}
		  - name: state
		    emptyDir: {}
	EOF
	kc wait --for=condition=Ready pod/impostor --timeout=300s >/dev/null || die "EV-04: the impostor KBS did not start"
	kc patch service trustee --type merge -p '{"spec":{"selector":{"app":"impostor"}}}' >/dev/null

	# Positive control: a workload that pins the impostor's certificate gets
	# the host's value, so the impostor works and only the pin differs.
	got=$(run_probe workload-imp "$(workload_initdata "" "$imp/tls.crt")")
	[[ $got == "$value" ]] || die "EV-04: the impostor served nothing even to a workload that pins its certificate ('$got'), so the eval proves nothing"
	got=$(run_probe workload-ok "$authorized")
	[[ $got == DENIED ]] || die "EV-04: a workload that pins Trustee's certificate got '$got' from the impostor"
	info "EV-04: the impostor served a workload that pins its certificate, and nothing to one that pins Trustee's"

	kc patch service trustee --type merge -p '{"spec":{"selector":{"app":"trustee-cvm"}}}' >/dev/null
	got=$(run_probe workload-again "$authorized")
	[[ $got == "$SECRET_VALUE" ]] || die "EV-04: with the Service back on Trustee, the workload got '$got'"
	info "EV-04: with the Service back on Trustee, the workload got its sealed resource"
	info "EV-04: pass"
}

# kbs_containers: the IDs of the operator's KBS containers. Podman records
# the image by digest, so match the name rather than an ancestor filter.
kbs_containers() {
	podman ps -a --format '{{.ID}} {{.Image}}' 2>/dev/null | awk '/key-broker-service/ {print $1}'
}

# leftovers <address> <run directory> <containers before>: what the first
# approve's Operator Verifier left behind, one item per line.
leftovers() {
	local c
	ss -Hltn "sport = :${1##*:}" | grep -q . && echo "a listener on $1"
	[[ -d $2 ]] && echo "the run directory $2$([[ -n $(find "$2" -path '*repository*' -type f 2>/dev/null) ]] && echo ', with the Share payload')"
	for c in $(kbs_containers); do
		grep -qx "$c" <<<"$3" || echo "the KBS container $c"
	done
	return 0
}

# EV-12: SIGKILL reaches approve while its Operator Verifier runs.
ev12() {
	section "EV-12: approve killed with SIGKILL"
	local ev=$work/ev12 listen=127.0.0.1:18090 approve addr rundir before dirs early left
	mkdir -p "$ev"
	baseline
	fresh_pod
	"$work/bin/attacker" -test.run '^TestAttack$' -test.v -attack hold -listen "$listen" -helper "$endpoint" >"$ev/attacker.log" 2>&1 &
	for _ in $(seq 30); do tb status --endpoint "http://$listen" >/dev/null 2>&1 && break; sleep 1; done
	before=$(kbs_containers)
	dirs=$(find "${XDG_RUNTIME_DIR:-/dev/shm}" -maxdepth 1 -name 'trustee-bootstrap-verifier-*' 2>/dev/null || true)
	# The binary itself, not the tb function: bash runs a backgrounded
	# function in a subshell, so $! would be that subshell, and kill -9
	# would leave approve running.
	"$work/bin/trustee-bootstrap" approve --endpoint "http://$listen" --policy "$work/policy-alice" \
		--share-file "$work/ceremony/alice.share" >"$ev/approve.out" 2>"$ev/approve.err" &
	approve=$!
	for _ in $(seq 60); do grep -q relay_opened "$ev/approve.err" && break; sleep 1; done
	grep -q relay_opened "$ev/approve.err" || die "EV-12: approve never opened the relay: $(tail -3 "$ev/approve.err")"
	addr=$(grep -o '"address":"[^"]*"' "$ev/approve.err" | head -1 | cut -d'"' -f4)
	rundir=$(find "${XDG_RUNTIME_DIR:-/dev/shm}" -maxdepth 1 -name 'trustee-bootstrap-verifier-*' | grep -vxF "$dirs" | head -1 || true)
	kill -9 "$approve"
	wait "$approve" 2>/dev/null || true
	sleep 5
	info "EV-12: after SIGKILL: $(leftovers "$addr" "$rundir" "$before" | paste -sd';' | sed 's/^$/nothing left/')"
	# The kernel stops the engine at once (Pdeathsig). Only the run
	# directory may wait for the next approve's sweep.
	early=$(leftovers "$addr" "" "$before")

	# Step 3: a second approve, against the real helper this time.
	expect_swept=1 approve_ok alice 1
	[[ -z $rundir || $out == *'"msg":"verifier_swept"'*"\"run\":\"${rundir##*/}\""* ]] ||
		die "EV-12: the second approve logged no sweep of ${rundir##*/}"
	info "EV-12: the second approve swept ${rundir##*/} and logged verifier_swept"
	left=$(leftovers "$addr" "$rundir" "$before")
	# Clean up whatever the killed run left, so later evals start clean.
	for c in $(kbs_containers); do
		grep -qx "$c" <<<"$before" || podman rm -f "$c" >/dev/null 2>&1 || true
	done
	[[ -z $rundir ]] || rm -rf "$rundir"
	[[ -z $early ]] || die "EV-12: 5 s after SIGKILL, these remain: $(paste -sd';' <<<"$early")"
	[[ -z $left ]] || die "EV-12: after SIGKILL and a second approve, these remain: $(paste -sd';' <<<"$left")"
	info "EV-12: pass"
}

# checklist <init.toml>: the Unlock Ceremony runbook's part 2, step 1, as a
# Security Operator runs it. Prints each check that flags, one per line.
checklist() {
	local t=$1
	[[ $(grep -o -- '--manifest-sha256=[0-9a-f]*' "$t" | sort -u) == "--manifest-sha256=$manifest_sha256" ]] || echo "manifest digest"
	[[ $(grep -o -- '--owner-[ug]id=[0-9]*' "$t" | sort -u | paste -sd' ') == "--owner-gid=0 --owner-uid=0" ]] || echo "Trustee's UID and GID"
	[[ $(grep -o 'bootstrap-helper@sha256:[0-9a-f]*' "$t" | sort -u) == "bootstrap-helper@${helper_image#*@}" ]] || echo "helper image digest"
	[[ $(grep -o 'key-broker-service[^"]*' "$t" | sort -u) == "key-broker-service${KBS_IMAGE#*key-broker-service}" ]] || echo "KBS image digest"
	[[ $(grep -c 'default ExecProcessRequest := false\|default ReadStreamRequest := false' "$t") == 2 ]] || echo "exec and log defaults"
	[[ $(grep -A2 '"ExecProcessRequest": {' "$t" | grep -c '": \[\]') == 2 ]] || echo "exec allow-lists"
	grep '"ReadStreamRequest"' "$t" | grep -q false || echo "log reads"
	[[ $(grep -o 'url = "[^"]*"' "$t" | sort -u) == 'url = "http://127.0.0.1:8081"' ]] || echo "KBS URL"
	[[ $(grep -o '"io.kubernetes.cri.container-name": "[^"]*"' "$t" | cut -d'"' -f4 | sort -u | paste -sd' ') == "bootstrap-helper trustee" ]] ||
		echo "container set"
	grep -q trustee_bootstrap_allow_image "$t" || echo "image pinning rule"
	return 0
}

# ev05_render <variant>: the pod, its Init-Data and genpolicy's settings,
# weakened one way, then genpolicy and the init.toml it wrote.
ev05_render() {
	local v=$ev/$1
	mkdir -p "$v/settings/genpolicy-settings.d"
	cp "$ev/pod.yaml" "$v/pod.yaml"
	cp "$work/init-data.toml" "$v/init-data.toml"
	cp "$gp/genpolicy-settings.json" "$v/settings/"
	cp "$gp"/genpolicy-settings.d/*.json "$v/settings/genpolicy-settings.d/"
	case $1 in
	tag) sed -i "s|$helper_image|${helper_image%@*}:1|" "$v/pod.yaml" ;;
	manifest) sed -i "s|--manifest-sha256=$manifest_sha256|--manifest-sha256=$other_sha256|" "$v/pod.yaml" ;;
	owner) sed -i 's|--owner-uid=0|--owner-uid=1000|' "$v/pod.yaml" ;;
	exec) echo '[{"op": "replace", "path": "/request_defaults/ExecProcessRequest/regex", "value": [".*"]}]' >"$v/settings/genpolicy-settings.d/eval.json" ;;
	logs) echo '[{"op": "replace", "path": "/request_defaults/ReadStreamRequest", "value": true}]' >"$v/settings/genpolicy-settings.d/eval.json" ;;
	kbs-url) sed -i 's|http://127.0.0.1:8081|http://10.0.0.1:8080|g' "$v/init-data.toml" ;;
	sidecar)
		# The helper's own image: genpolicy takes it as it is, and the
		# sidecar adds no image digest for the checklist to spot.
		python3 - "$v/pod.yaml" "$helper_image" <<-'EOF'
			import sys
			path, image = sys.argv[1], sys.argv[2]
			s = open(path).read()
			side = f'    - name: sidecar\n      image: {image}\n'
			assert s.count("    - name: trustee\n") == 1
			open(path, "w").write(s.replace("    - name: trustee\n", side + "    - name: trustee\n"))
		EOF
		;;
	# Trustee's container from another image that the registry already holds.
	kbs-image) sed -i "s|$KBS_IMAGE|$helper_image|" "$v/pod.yaml" ;;
	esac
	local rules=$gp/rules.rego
	[[ $1 != upstream-rules ]] || rules=$gp/rules.upstream.rego
	"$gp/genpolicy" -y "$v/pod.yaml" -p "$rules" -j "$v/settings" --initdata-path="$v/init-data.toml" \
		--insecure-registry="$registry" >"$v/genpolicy.log" 2>&1 || die "EV-05: genpolicy failed on $1: $(tail -3 "$v/genpolicy.log")"
	extract_initdata "$v/pod.yaml" "$v/init.toml"
}

# EV-05: the review checklist against Init-Data weakened eight ways.
ev05() {
	section "EV-05: Security Operator reviews a weakened Init-Data"
	local name caught missed=()
	ev=$work/ev05
	mkdir -p "$ev/other"
	manifest_sha256=$(sha256sum "$work/ceremony/ceremony.json" | cut -d' ' -f1)
	tb ceremony split --threshold 2 --holders x,y --out-dir "$ev/other" >/dev/null
	other_sha256=$(sha256sum "$ev/other/ceremony.json" | cut -d' ' -f1)
	# The pod before genpolicy, as render_pod builds it.
	sed "s|@HELPER_IMAGE@|$helper_image|; s|@MANIFEST_SHA256@|$manifest_sha256|" "$examples/trustee-cvm.yaml" >"$ev/pod.yaml"
	for name in base tag manifest owner exec logs kbs-url sidecar kbs-image upstream-rules; do
		ev05_render "$name"
		caught=$(checklist "$ev/$name/init.toml" | paste -sd, -)
		if [[ $name == base ]]; then
			[[ -z $caught ]] || die "EV-05: the unchanged Init-Data fails the checklist: $caught"
			info "EV-05: base: passes every check"
		elif [[ -n $caught ]]; then
			info "EV-05: $name: caught by $caught"
		else
			info "EV-05: $name: no check catches it"
			missed+=("$name")
		fi
	done
	((${#missed[@]} == 0)) || die "EV-05: the checklist misses: ${missed[*]}"
	info "EV-05: pass"
}

# fault <name> <text> <output>: the runbook quotes text, and output shows it.
fault() {
	grep -qF -- "$2" "$repo/docs/runbooks/unlock-ceremony.md" || die "EV-06: $1: the runbook no longer quotes '$2'"
	[[ $3 == *"$2"* ]] || die "EV-06: $1: the output was '${3:0:300}', but the runbook quotes '$2'"
	info "EV-06: $1: shows '$2', as the runbook says"
}

# EV-06: each failure the Unlock Ceremony runbook names, injected.
ev06() {
	section "EV-06: Runbook error paths match the CLI"
	local ev=$work/ev06 out hold
	mkdir -p "$ev/other" "$ev/disk"
	baseline
	fresh_pod

	(
		bundle_sha256=$(printf '0%.0s' $(seq 64))
		policy_build alice "$ev/policy-other-bundle"
	) >/dev/null
	out=$(tb approve --endpoint "$endpoint" --policy "$ev/policy-other-bundle" --share-file "$work/ceremony/alice.share" 2>&1) &&
		die "EV-06: an approve for another bundle succeeded"
	fault "wrong bundle" "Share not accepted" "$out"
	out=$(tb status --endpoint "$endpoint")
	expect_status "$key_id COLLECTING 2 [] [1]"

	sed '1i # other Init-Data' "$work/init.toml" >"$ev/init-other.toml"
	(
		init_toml=$ev/init-other.toml
		policy_build carol "$ev/policy-other-init"
	) >/dev/null
	out=$(tb approve --endpoint "$endpoint" --policy "$ev/policy-other-init" --share-file "$work/ceremony/carol.share" 2>&1) &&
		die "EV-06: an approve for other Init-Data succeeded"
	fault "wrong Init-Data" "relay ended" "$out"
	out=$(tb status --endpoint "$endpoint")
	expect_status "$key_id COLLECTING 2 [] [1]"
	info "EV-06: wrong Init-Data: Carol's index stays out of rejected, as the runbook says"

	# Someone else holds the helper's one relay: a raw WebSocket upgrade.
	curl -sN --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
		-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$endpoint/bootstrap/v1/relay" >/dev/null 2>&1 &
	hold=$!
	sleep 2
	out=$(tb approve --endpoint "$endpoint" --policy "$work/policy-carol" --share-file "$work/ceremony/carol.share" 2>&1) &&
		die "EV-06: approve opened a second relay"
	kill "$hold" 2>/dev/null || true
	wait "$hold" 2>/dev/null || true
	fault "relay held" "open relay:" "$out"
	[[ $out == *409* ]] || die "EV-06: relay held: no 409 in '${out:0:300}'"
	sleep 5

	approve_ok alice 1
	out=$(tb approve --endpoint "$endpoint" --policy "$work/policy-alice" --share-file "$work/ceremony/alice.share" 2>&1) &&
		die "EV-06: a second approve for the same index succeeded"
	fault "approve twice" "already accepted this boot" "$out"

	tb ceremony split --threshold 2 --holders x,y --out-dir "$ev/other" >/dev/null
	(
		ceremony_dir=$ev/other
		policy_build x "$ev/policy-x"
	) >/dev/null
	out=$(tb approve --endpoint "$endpoint" --policy "$ev/policy-x" --share-file "$ev/other/x.share" 2>&1) &&
		die "EV-06: an approve with another ceremony's Share succeeded"
	fault "another ceremony's Share" "the Bootstrap Helper has key_id" "$out"

	[[ $(stat -f -c %T "$ev/disk") != tmpfs ]] || die "EV-06: $ev/disk is on tmpfs, so the fault can't be injected here"
	out=$(XDG_RUNTIME_DIR=$ev/disk tb approve --endpoint "$endpoint" --policy "$work/policy-carol" \
		--share-file "$work/ceremony/carol.share" 2>&1) && die "EV-06: approve ran its Operator Verifier from a disk directory"
	fault "run directory on disk" "start Operator Verifier:" "$out"
	fault "run directory on disk" "is not on tmpfs" "$out"

	grep -qF 'Init:Error' "$repo/docs/runbooks/unlock-ceremony.md" || die "EV-06: the runbook no longer names Init:Error"
	check_swapped_manifest
	kc create configmap trustee-ceremony-manifest --from-file=ceremony.json=/dev/stdin --dry-run=client -o yaml \
		<"$work/ceremony/ceremony.json" | kc apply -f - >/dev/null 2>&1
	info "EV-06: swapped manifest: the helper exited 1 and status never answered, as the runbook says"

	grep -qF 'CreateContainerRequest is blocked by policy' "$repo/docs/runbooks/unlock-ceremony.md" ||
		die "EV-06: the runbook no longer quotes the policy event"
	check_tampered
	info "EV-06: stale genpolicy: the event says CreateContainerRequest is blocked by policy, as the runbook says"

	head -c 1100000 /dev/urandom >"$ev/big.age"
	out=$(kc create configmap ev06-big --from-file=bundle.age=/dev/stdin --dry-run=server <"$ev/big.age" 2>&1) &&
		die "EV-06: the API server accepted a ConfigMap over 1 MiB"
	info "EV-06: oversized bundle: the API server refuses a ConfigMap over 1 MiB ($(grep -o 'Too long[^"]*' <<<"$out" | head -1)), so a bundle that size never reaches the helper"
	info "EV-06: pass"
}

# attacker <log> <flags...>: the relay attacker at $listen, in the
# background; waits until its status passthrough answers.
attacker() {
	local log=$1
	shift
	"$work/bin/attacker" -test.run '^TestAttack$' -test.v -listen "$listen" "$@" >"$log" 2>&1 &
	for _ in $(seq 30); do
		tb status --endpoint "http://$listen" >/dev/null 2>&1 && return
		sleep 1
	done
	die "the attacker did not start: $(tail -3 "$log")"
}

# EV-03: Alice withdraws bundle A after her Share went in, but the host
# keeps the old boot and shows a forged, empty status in its place.
ev03() {
	section "EV-03: Host ignores a withdrawal"
	local ev=$work/ev03 listen=127.0.0.1:18091 real
	mkdir -p "$ev/tree-b"
	baseline
	fresh_pod
	approve_ok alice 1
	out=$(tb status --endpoint "$endpoint")
	expect_status "$key_id COLLECTING 2 [1] []"
	real=$boot_id
	info "EV-03: Alice released her Share for bundle A, then withdrew"

	# Carol rebuilds her policy for B; Bob, compromised, keeps A.
	cp -r "$work/tree/." "$ev/tree-b/"
	printf 'b-%s' "$SECRET_VALUE" >"$ev/tree-b/storage/repository/${SECRET//\//\\x2F}"
	tb seal --manifest "$work/ceremony/ceremony.json" --output "$ev/b.age" "$ev/tree-b" >/dev/null
	(
		bundle_sha256=$(sha256sum "$ev/b.age" | cut -d' ' -f1)
		policy_build carol "$ev/policy-carol-b"
	) >/dev/null
	policy_build bob >/dev/null

	attacker "$ev/attacker.log" -attack pass -forge-status -helper "$endpoint" -evidence "$ev/evidence.json"
	out=$(tb status --endpoint "http://$listen")
	expect_status "$key_id COLLECTING 2 [] []"
	[[ $boot_id != "$real" ]] || die "EV-03: the forged status kept the real boot_id"
	info "EV-03: the host's endpoint shows a new boot_id and no Shares, so the withdraw runbook's step 4 looks done"

	out=$(tb approve --endpoint "http://$listen" --policy "$ev/policy-carol-b" --share-file "$work/ceremony/carol.share" 2>&1) &&
		die "EV-03: the old boot accepted Carol's Share for B"
	wait
	out=$(tb status --endpoint "$endpoint")
	expect_status "$key_id COLLECTING 2 [1] [3]"
	[[ $boot_id == "$real" && $(ready) == False ]] || die "EV-03: the old boot changed or started"
	info "EV-03: the old boot rejected Carol's Share for B and stays locked with only Alice's"

	approve_ok bob 2
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "EV-03: Bob's Share didn't unlock A"
	info "EV-03: Bob's Share unlocked A: the documented residual risk, which takes the host and a compromised Security Operator"
	info "EV-03: pass"
}

# EV-13: the host drops Alice's relay at two points of her approve run.
ev13() {
	section "EV-13: Relay cut after release"
	local ev=$work/ev13 listen=127.0.0.1:18092 cut before dirs addr rundir left tries
	mkdir -p "$ev"
	baseline
	for cut in cut-attest cut-close; do
		fresh_pod
		attacker "$ev/$cut.log" -attack "$cut" -helper "$endpoint" -evidence "$ev/evidence.json"
		before=$(kbs_containers)
		dirs=$(find "${XDG_RUNTIME_DIR:-/dev/shm}" -maxdepth 1 -name 'trustee-bootstrap-verifier-*' 2>/dev/null || true)
		out=$(tb approve --endpoint "http://$listen" --policy "$work/policy-alice" --share-file "$work/ceremony/alice.share" 2>&1) &&
			die "EV-13: $cut: approve reported success over a cut relay"
		[[ $out == *"relay ended"* ]] || die "EV-13: $cut: approve said '${out:0:200}'"
		wait
		addr=$(grep -o '"address":"[^"]*"' <<<"$out" | head -1 | cut -d'"' -f4)
		rundir=$(find "${XDG_RUNTIME_DIR:-/dev/shm}" -maxdepth 1 -name 'trustee-bootstrap-verifier-*' | grep -vxF "$dirs" | head -1 || true)
		left=$(leftovers "$addr" "$rundir" "$before")
		[[ -z $left ]] || die "EV-13: $cut: approve left behind: $(paste -sd';' <<<"$left")"
		out=$(tb status --endpoint "$endpoint")
		if [[ $cut == cut-attest ]]; then
			expect_status "$key_id COLLECTING 2 [] []"
			info "EV-13: cut-attest: approve failed with 'relay ended', left nothing behind, and the helper holds no Share"
			# The helper takes a new relay once it has closed the cut one.
			for tries in $(seq 10); do
				out=$(tb approve --endpoint "$endpoint" --policy "$work/policy-alice" --share-file "$work/ceremony/alice.share" 2>&1) && break
				[[ $out == *409* ]] || die "EV-13: cut-attest: the retry failed: ${out:0:200}"
				sleep 2
			done
			[[ ${out##*$'\n'} == accepted ]] || die "EV-13: cut-attest: the retry never got through"
			info "EV-13: cut-attest: the retry was accepted on try $tries"
		else
			expect_status "$key_id COLLECTING 2 [1] []"
			info "EV-13: cut-close: approve failed with 'relay ended' and left nothing behind, but the helper accepted the Share"
			out=$(tb approve --endpoint "$endpoint" --policy "$work/policy-alice" --share-file "$work/ceremony/alice.share" 2>&1) &&
				die "EV-13: cut-close: a second approve for an accepted index succeeded"
			[[ $out == *"already accepted this boot"* ]] || die "EV-13: cut-close: the retry said '${out:0:200}'"
			info "EV-13: cut-close: the retry said 'index 1 already accepted this boot'"
			approve_ok carol 3
			kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "EV-13: Carol's Share didn't complete the unlock"
			info "EV-13: cut-close: Carol's Share completed the unlock with two distinct indices"
		fi
	done
	info "EV-13: pass"
}

# clone_cvm <namespace> <rendered pod>: the pod, the setup's manifest and
# bundle, and the helper's Service in another namespace. Prints its URL.
clone_cvm() {
	kc create namespace "$1" >/dev/null
	kc -n "$1" create configmap trustee-ceremony-manifest --from-file=ceremony.json=/dev/stdin <"$work/ceremony/ceremony.json" >/dev/null
	kc -n "$1" create configmap trustee-sealed-bundle --from-file=bundle.age=/dev/stdin <"$work/bundle.age" >/dev/null
	kc -n "$1" apply -f - <"$2" >/dev/null
	echo "http://$(kc get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'):$(
		kc -n "$1" get service "$HELPER_SVC" -o jsonpath='{.spec.ports[0].nodePort}')"
}

# answers <url>: the helper at url serves status within 300 s.
answers() {
	for _ in $(seq 150); do
		tb status --endpoint "$1" >/dev/null 2>&1 && return 0
		sleep 2
	done
	return 1
}

# EV-02: one approve run, spliced by the host to every CVM it can reach.
ev02() {
	section "EV-02: Host splices one approval into several CVMs"
	local ev=$work/ev02 listen=127.0.0.1:18093 e1 e2 ex helpers line fed=0 url
	mkdir -p "$ev"
	trap 'kc delete namespace evals-clone evals-other --ignore-not-found --wait=false >/dev/null 2>&1' EXIT
	baseline
	fresh_pod
	e1=$endpoint
	# cvm-2: the same rendered pod, so the same Init-Data, in another namespace.
	e2=$(clone_cvm evals-clone "$work/trustee-cvm.yaml")
	# cvm-x: other Init-Data, a lower relay idle limit, in a third namespace.
	sed "s|@HELPER_IMAGE@|$helper_image|; s|@MANIFEST_SHA256@|$(sha256sum "$work/ceremony/ceremony.json" | cut -d' ' -f1)|" \
		"$examples/trustee-cvm.yaml" | sed 's|^\( *\)- --proxy-port=8081$|&\n\1- --relay-idle-timeout=29s|' >"$ev/x.yaml"
	"$gp/genpolicy" -y "$ev/x.yaml" -p "$gp/rules.rego" -j "$gp" --initdata-path="$work/init-data.toml" \
		--insecure-registry="$registry" >/dev/null
	ex=$(clone_cvm evals-other "$ev/x.yaml")
	helpers=$e1
	if answers "$e2"; then
		helpers+=,$e2
		info "EV-02: a second approved CVM runs in another namespace"
	else
		info "EV-02: the approved pod did not start in another namespace: $(kc -n evals-clone get events -o jsonpath='{.items[*].message}' | grep -o '[A-Za-z]*Request is blocked by policy' | head -1)"
	fi
	answers "$ex" || die "EV-02: the CVM with other Init-Data never answered"
	helpers+=,$ex

	attacker "$ev/attacker.log" -attack splice -helper "$e1" -helpers "$helpers"
	tb approve --endpoint "http://$listen" --policy "$work/policy-alice" --share-file "$work/ceremony/alice.share" >"$ev/approve.log" 2>&1 || true
	wait
	for url in ${helpers//,/ }; do
		line=$(grep -o "splice: $url: .*" "$ev/attacker.log" | head -1)
		[[ -n $line ]] || die "EV-02: the attacker never reached $url"
		info "EV-02: $line"
		if [[ $url == "$ex" ]]; then
			[[ $line == *released=false* ]] || die "EV-02: the CVM with other Init-Data got the Share"
		elif [[ $line == *released=true*close=1000* ]]; then
			fed=$((fed + 1))
		fi
	done
	((fed >= 1 && fed <= 4)) || die "EV-02: one approve run fed $fed approved CVMs"
	info "EV-02: one approve run fed $fed approved CVMs, and none with other Init-Data"
	info "EV-02: pass"
}

# start_pod <yaml>: replace the Trustee CVM with this rendered pod and wait
# for its helper.
start_pod() {
	kc delete pod "$POD" --ignore-not-found --wait >/dev/null
	kc apply -f - <"$1" >/dev/null
	endpoint=$(helper_endpoint)
	wait_helper
}

# EV-09: trustee-upgrade.md for a new helper image, its faults, the
# rollback, and then a config upgrade whose old bundle the host remounts.
ev09() {
	section "EV-09: Upgrade the Bootstrap Helper and roll back"
	local ev=$work/ev09 v2 out request holder
	mkdir -p "$ev/tree-b"
	baseline
	fresh_pod
	unlock_pod
	info "EV-09: v1 runs, unlocked"

	# v2: the same source with an extra label, so it gets a new digest.
	eng build -q --timestamp 0 --identity-label=false --label eval=v2 -f "$repo/cmd/bootstrap-helper/Containerfile" \
		-t "$registry/trustee-bootstrap/bootstrap-helper:v2" "$repo" >/dev/null
	eng push -q --tls-verify=false --digestfile "$ev/digest-v2" "$registry/trustee-bootstrap/bootstrap-helper:v2"
	eng rmi "$registry/trustee-bootstrap/bootstrap-helper:v2" >/dev/null
	v2=$registry/trustee-bootstrap/bootstrap-helper@$(cat "$ev/digest-v2")
	[[ $v2 != "$helper_image" ]] || die "EV-09: v2 got v1's digest"
	sed "s|@HELPER_IMAGE@|$v2|; s|@MANIFEST_SHA256@|$(sha256sum "$work/ceremony/ceremony.json" | cut -d' ' -f1)|" \
		"$examples/trustee-cvm.yaml" >"$ev/v2.yaml"
	"$gp/genpolicy" -y "$ev/v2.yaml" -p "$gp/rules.rego" -j "$gp" --initdata-path="$work/init-data.toml" \
		--insecure-registry="$registry" >/dev/null
	extract_initdata "$ev/v2.yaml" "$ev/init-v2.toml"
	(
		init_toml=$ev/init-v2.toml
		policy_build alice "$ev/policy-alice-v2"
		policy_build carol "$ev/policy-carol-v2"
	) >/dev/null

	start_pod "$ev/v2.yaml"
	out=$(tb approve --endpoint "$endpoint" --policy "$work/policy-alice" --share-file "$work/ceremony/alice.share" 2>&1) &&
		die "EV-09: Alice's v1 Operator Policy released to the v2 pod"
	out=$(tb status --endpoint "$endpoint")
	expect_status "$key_id COLLECTING 2 [] []"
	info "EV-09: fault 1: Alice's v1 policy released nothing to the v2 pod, and her index stayed out of rejected"

	kc delete pod "$POD" --ignore-not-found --wait >/dev/null
	sed "s|$v2|$helper_image|" "$ev/v2.yaml" | kc apply -f - >/dev/null
	request=$(blocked_by_policy)
	[[ $request == "CreateContainerRequest is blocked by policy" ]] ||
		die "EV-09: fault 2: a hand-edited digest without genpolicy gave '${request:-no policy event}', not what the runbook names"
	info "EV-09: fault 2: a hand-edited digest without genpolicy: $request"

	start_pod "$ev/v2.yaml"
	approve_ok alice 1 "$ev/policy-alice-v2"
	approve_ok carol 3 "$ev/policy-carol-v2"
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "EV-09: v2 did not become Ready"
	RESOURCE=$SECRET
	[[ $(run_probe workload-ok "$authorized") == "$SECRET_VALUE" ]] || die "EV-09: after the upgrade, the workload got nothing"
	info "EV-09: v2 unlocked with the v2 policies and served the workload"

	fresh_pod
	unlock_pod
	info "EV-09: rollback: v1 unlocked again with the v1 policies, with no new review"

	# Config pass: bundle B and new policies for it; the host remounts A.
	cp -r "$work/tree/." "$ev/tree-b/"
	printf 'b-%s' "$SECRET_VALUE" >"$ev/tree-b/storage/repository/${SECRET//\//\\x2F}"
	tb seal --manifest "$work/ceremony/ceremony.json" --output "$ev/b.age" "$ev/tree-b" >/dev/null
	(
		bundle_sha256=$(sha256sum "$ev/b.age" | cut -d' ' -f1)
		policy_build alice "$ev/policy-alice-b"
		policy_build carol "$ev/policy-carol-b"
	) >/dev/null
	baseline
	fresh_pod
	for holder in alice carol; do
		out=$(tb approve --endpoint "$endpoint" --policy "$ev/policy-$holder-b" --share-file "$work/ceremony/$holder.share" 2>&1) &&
			die "EV-09: $holder's Share for B unlocked bundle A"
	done
	out=$(tb status --endpoint "$endpoint")
	expect_status "$key_id COLLECTING 2 [] [1,3]"
	[[ $(ready) == False ]] || die "EV-09: Trustee started on the old bundle"
	info "EV-09: config pass: with A remounted, both Shares for B were rejected and Trustee did not start"
	info "EV-09: pass"
}

# EV-10: roster-change.md, then Carol, who left, tries her old Share.
ev10() {
	section "EV-10: Roster change locks out a departed operator"
	local ev=$work/ev10 new_key out
	mkdir -p "$ev/ceremony"
	trap 'baseline' EXIT
	baseline
	fresh_pod
	unlock_pod

	# Steps 1 and 2: a new Key Ceremony, and bundle B with new keys and a
	# new secret, sealed to it. trustee_tree in a subshell writes $ev/tree.
	tb ceremony split --threshold 2 --holders alice,bob,dave --out-dir "$ev/ceremony" >/dev/null
	(
		work=$ev
		SECRET_VALUE=roster-$SECRET_VALUE
		trustee_tree
		printf '%s' "$authorized" >"$ev/authorized.toml"
	)
	tb seal --manifest "$ev/ceremony/ceremony.json" --output "$ev/bundle.age" "$ev/tree" >/dev/null
	new_key=$(jq -r .key_id "$ev/ceremony/ceremony.json")

	# Step 3: the new manifest, bundle and pod.
	sed "s|@HELPER_IMAGE@|$helper_image|; s|@MANIFEST_SHA256@|$(sha256sum "$ev/ceremony/ceremony.json" | cut -d' ' -f1)|" \
		"$examples/trustee-cvm.yaml" >"$ev/trustee-cvm.yaml"
	"$gp/genpolicy" -y "$ev/trustee-cvm.yaml" -p "$gp/rules.rego" -j "$gp" --initdata-path="$work/init-data.toml" \
		--insecure-registry="$registry" >/dev/null
	extract_initdata "$ev/trustee-cvm.yaml" "$ev/init.toml"
	set_manifest "$ev/ceremony/ceremony.json"
	set_bundle "$ev/bundle.age"
	start_pod "$ev/trustee-cvm.yaml"
	out=$(tb status --endpoint "$endpoint")
	expect_status "$new_key COLLECTING 2 [] []"

	# Step 4: Alice and Bob approve with policies for the new roster.
	(
		ceremony_dir=$ev/ceremony init_toml=$ev/init.toml
		bundle_sha256=$(sha256sum "$ev/bundle.age" | cut -d' ' -f1)
		policy_build alice "$ev/policy-alice"
		policy_build bob "$ev/policy-bob"
	) >/dev/null
	approve_ok alice 1 "$ev/policy-alice" "$ev/ceremony/alice.share"
	approve_ok bob 2 "$ev/policy-bob" "$ev/ceremony/bob.share"
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "EV-10: the new roster's Trustee did not become Ready"
	RESOURCE=$SECRET
	[[ $(run_probe workload-new "$(cat "$ev/authorized.toml")") == "roster-$SECRET_VALUE" ]] ||
		die "EV-10: a workload that pins the new certificate got nothing"
	info "EV-10: the new roster unlocked B, with key_id $new_key"

	# 2.4: B shares no key or secret with A, and A's certificate no longer works.
	cmp -s "$work/tree/tls.key" "$ev/tree/tls.key" && die "EV-10: B reuses A's TLS key"
	cmp -s "$work/tree/tls.crt" "$ev/tree/tls.crt" && die "EV-10: B reuses A's certificate"
	[[ $(run_probe workload-ok "$authorized") == DENIED ]] || die "EV-10: a workload that pins A's certificate still reached Trustee"
	kc delete pod workload-new workload-ok --wait=false >/dev/null
	info "EV-10: B has a new TLS key, certificate and secret, and a workload that pins A's certificate gets nothing"

	# 2.1 and 2.2: Carol tries her old Share.
	out=$(tb policy build --init-data "$ev/init.toml" --reference-values "$work/rv.json" --accept-tee tpm --allow-untested-profiles \
		--bundle-sha256 "$(sha256sum "$ev/bundle.age" | cut -d' ' -f1)" --manifest "$ev/ceremony/ceremony.json" \
		--share-file "$work/ceremony/carol.share" --out-dir "$ev/policy-carol" 2>&1) &&
		die "EV-10: policy build took Carol's old Share for the new ceremony"
	info "EV-10: policy build refused Carol's old Share: $(head -1 <<<"$out")"
	start_pod "$ev/trustee-cvm.yaml"
	out=$(tb approve --endpoint "$endpoint" --policy "$work/policy-carol" --share-file "$work/ceremony/carol.share" 2>&1) &&
		die "EV-10: Carol's old Share reached the new pod"
	[[ $out == *"the Bootstrap Helper has key_id"* ]] || die "EV-10: approve refused Carol's old Share, but said '${out:0:200}'"
	info "EV-10: approve stopped Carol's old Share at the key_id check"
	info "EV-10: 2.3 (a forged payload with the new key_id) runs in go test: pkg/helper, AT-08"
	info "EV-10: pass"
}

# EV-14: a resource policy that doesn't parse passes the sealed-config
# checks, so the helper publishes it.
ev14() {
	section "EV-14: Broken sealed resource policy"
	local code
	mkdir -p "$work/broken-tree"
	cp -r "$work/tree/." "$work/broken-tree/"
	printf 'package policy\n\ndefault allow := false\n\nallow if {\n' >"$work/broken-tree/storage/kbs/resource-policy.rego"
	tb seal --manifest "$work/ceremony/ceremony.json" --output "$work/broken.age" "$work/broken-tree" >/dev/null ||
		die "EV-14: seal refused the broken policy, so no helper ever sees one"
	(
		bundle_sha256=$(sha256sum "$work/broken.age" | cut -d' ' -f1)
		policy_build alice "$work/policy-alice-broken"
		policy_build carol "$work/policy-carol-broken"
	) >/dev/null
	baseline
	set_bundle "$work/broken.age"
	fresh_pod
	approve_ok alice 1 "$work/policy-alice-broken"
	approve_ok carol 3 "$work/policy-carol-broken"
	status_refused
	code=$(pod "$POD" '{.status.initContainerStatuses[0].state.terminated.exitCode}')
	for _ in $(seq 60); do
		[[ $(ready) == True ]] && break
		sleep 2
	done
	info "EV-14: the helper exited ${code:-?}, and Trustee is $([[ $(ready) == True ]] && echo Ready || echo 'not Ready')"
	RESOURCE=$SECRET
	[[ $(run_probe workload-ok "$authorized") == DENIED ]] || die "EV-14: the authorized workload got a resource under a broken policy"
	[[ $(run_probe workload-other "$unauthorized") == DENIED ]] ||
		die "EV-14: the unauthorized workload got a resource: KBS fell back to its built-in default policy"
	kc delete pod workload-ok workload-other --wait=false >/dev/null
	info "EV-14: pass"
}

main() {
	trap 'kc delete pod bundle-probe impostor --ignore-not-found --wait=false >/dev/null 2>&1; cleanup' EXIT
	deploy_cvm >/dev/null
	local ev evs=("$@") failed=()
	((${#evs[@]})) || evs=(ev05 ev06 ev14 ev04 ev03 ev13 ev02 ev09 ev10 ev12)
	for ev in "${evs[@]}"; do
		case $ev in
		ev02 | ev03 | ev04 | ev05 | ev06 | ev09 | ev10 | ev12 | ev13 | ev14) ("$ev") || failed+=("$ev") ;;
		*) die "usage: $0 [ev02|ev03|ev04|ev05|ev06|ev09|ev10|ev12|ev13|ev14 ...]" ;;
		esac
	done
	((${#failed[@]} == 0)) || die "failed: ${failed[*]}"
	info "PASS"
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
