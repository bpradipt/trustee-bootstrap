#!/usr/bin/env bash
# The healthy-path evals EV-16 to EV-19 (docs/evals) on the kind + Kata +
# swtpm cluster from kind-kata-swtpm.sh (run its `up` first): one working
# Unlock Ceremony, from deploy to a workload holding its key, then a Trustee
# container restart.
#
#   golden-path.sh       run all four evals. stdout is the transcript: each
#                        command as an operator types it and what came back.
#                        Fails at the first answer that differs from what
#                        the eval docs expect; prints PASS on stderr.
#   golden-path.sh hil   human in the loop: deploy the Trustee CVM, stop
#                        where EV-16 starts, and write $work/hil.env. Source
#                        it, and the commands in the eval docs run as
#                        written. Leaves everything in place.
#
# Needs what trustee-cvm.sh needs. Set E2E_WORK to choose the work directory.
# shellcheck disable=SC2016 # the transcript and hil.env keep $ENDPOINT and $work unexpanded
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=trustee-cvm.sh
source "$script_dir/trustee-cvm.sh"
info() { echo "[golden-path] $*" >&2; }
die() { echo "[golden-path] FAIL: $*" >&2; exit 1; }

EVENT_COLUMNS=TYPE:.type,REASON:.reason,OBJECT:.involvedObject.fieldPath,MESSAGE:.message

# show <label> <command...>: run the command and print the label and its
# output to the transcript. Leaves them in $out and $rc for the checks.
show() {
	local label=$1
	shift
	rc=0
	out=$("$@" 2>&1) || rc=$?
	printf '\n$ %s\n%s\n' "$label" "$out"
	((rc == 0)) || printf '[exit %d]\n' "$rc"
}

section() { printf '\n######## %s\n' "$*"; }
pod() { kc get pod "$1" -o jsonpath="$2"; }
events() { kc get events --field-selector "involvedObject.name=$1" --sort-by=.lastTimestamp -o "custom-columns=$2"; }
show_events() { show "kubectl get events --field-selector involvedObject.name=$1 --sort-by=.lastTimestamp -o custom-columns=$2" events "$1" "$2"; }
warnings() { grep '^Warning' <<<"$out" || true; }

# has_row <column>...: $out has a line that starts with these columns.
has_row() { grep -Eq "^$(printf '%s +' "$@")" <<<"$out"; }

# expect_status <want>: $out is a status whose fields after boot_id are
# <want>. Sets boot_id.
expect_status() {
	local got
	got=$(python3 -c 'import json, sys
s = json.load(sys.stdin)
c = lambda v: json.dumps(v, separators=(",", ":"))
print(s["boot_id"], s["key_id"], s["state"], s["threshold"], c(s["accepted"]), c(s["rejected"]))' <<<"$out") ||
		die "status did not answer JSON: $out"
	boot_id=${got%% *}
	[[ ${got#* } == "$1" ]] || die "status is '${got#* }', want '$1'"
}

show_status() { show 'trustee-bootstrap status --endpoint "$ENDPOINT"' tb status --endpoint "$endpoint"; }

# status_refused: the helper published and exited, so status stops
# answering within 30 s.
status_refused() {
	for _ in $(seq 15); do
		tb status --endpoint "$endpoint" >/dev/null 2>&1 || break
		sleep 2
	done
	show_status
	if ((rc == 0)) || [[ $out != *"connection refused"* ]]; then die "the helper still answers status: $out"; fi
}

# approve_ok <holder> <index>: the holder's approve is accepted, and its
# audit records tell the whole run without the Share.
approve_ok() {
	local msgs share
	show "trustee-bootstrap approve --endpoint \"\$ENDPOINT\" --policy ~/trustee-policy --share-file $1.share" \
		tb approve --endpoint "$endpoint" --policy "$work/policy-$1" --share-file "$work/ceremony/$1.share"
	((rc == 0)) || die "$1's approve failed"
	[[ ${out##*$'\n'} == accepted ]] || die "$1's approve did not print accepted"
	msgs=$(grep -o '"msg":"[a-z_]*"' <<<"$out" | cut -d'"' -f4 | paste -sd' ')
	[[ $msgs == "verifier_started relay_opened relay_closed verifier_stopped approve_result" ]] ||
		die "$1's audit records: $msgs"
	[[ $out == *'"index":'"$2,"*'"code":1000'*'"accepted":true'* ]] ||
		die "$1's audit records lack index $2, close code 1000 or accepted"
	share=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["share"])' "$work/ceremony/$1.share")
	[[ $out != *"$share"* ]] || die "$1's approve printed the Share"
}

# operator_policies: Alice and Carol each build an Operator Policy from the
# same init.toml and get the same Init-Data digest.
operator_policies() {
	local holder digest digests=()
	for holder in alice carol; do
		show "trustee-bootstrap policy build --init-data init.toml ... --share-file $holder.share --out-dir ~/trustee-policy" \
			policy_build "$holder"
		((rc == 0)) || die "$holder's policy build failed"
		digest=$(grep -Eo '^init_data_sha256 [0-9a-f]{64}$' <<<"$out") || die "$holder's policy build printed no digest"
		digests+=("$digest")
	done
	[[ ${digests[0]} == "${digests[1]}" ]] || die "the Security Operators' Init-Data digests differ: ${digests[*]}"
}

ev16() {
	section "EV-16: Deployed Trustee CVM waits for Shares"
	show "kubectl get pod $POD" kc get pod "$POD"
	has_row "$POD" 0/1 Init:0/1 0 || die "the pod is not 0/1 Init:0/1 with 0 restarts"
	show "kubectl get service $HELPER_SVC trustee" kc get service "$HELPER_SVC" trustee
	show "kubectl get endpoints $HELPER_SVC trustee" kc get endpoints "$HELPER_SVC" trustee
	has_row "$HELPER_SVC" "$pod_ip:8090" || die "the helper Service has no endpoint while the pod is not Ready"
	grep -Eq '^trustee +[0-9][0-9smhd]*$' <<<"$out" || die "the trustee Service has an endpoint before the unlock"
	show_status
	expect_status "$key_id COLLECTING 2 [] []"
	first_boot=$boot_id
	info "EV-16: pass"
}

ev17() {
	section "EV-17: Two Security Operators unlock Trustee"
	approve_ok alice 1
	show_status
	expect_status "$key_id COLLECTING 2 [1] []"
	[[ $boot_id == "$first_boot" ]] || die "boot_id changed from $first_boot to $boot_id"
	show "kubectl get pod $POD" kc get pod "$POD"
	has_row "$POD" 0/1 Init:0/1 0 || die "the pod moved on with one Share of two"
	approve_ok carol 3
	status_refused
	show "kubectl wait --for=condition=Ready pod/$POD --timeout=600s" kc wait --for=condition=Ready "pod/$POD" --timeout=600s
	((rc == 0)) || die "Trustee did not become Ready"
	show "kubectl get pod $POD" kc get pod "$POD"
	has_row "$POD" 1/1 Running 0 || die "the pod is not 1/1 Running with 0 restarts"
	show "kubectl get pod $POD -o jsonpath='{.status.initContainerStatuses[0].state.terminated}'" \
		pod "$POD" '{.status.initContainerStatuses[0].state.terminated}'
	[[ $out == *'"exitCode":0,'*'"reason":"Completed"'* ]] || die "the helper did not exit 0"
	show "kubectl get endpoints $HELPER_SVC trustee" kc get endpoints "$HELPER_SVC" trustee
	has_row trustee "$pod_ip:8080" || die "the trustee Service has no endpoint after the unlock"
	show_events "$POD" "$EVENT_COLUMNS"
	if warnings | grep -Evq 'Unhealthy +spec\.containers\{trustee\} +Readiness probe failed'; then
		die "unexpected Warning events: $(warnings)"
	fi
	for c in bootstrap-helper trustee; do
		show "kubectl logs $POD -c $c" kc logs "$POD" -c "$c"
		((rc == 0)) || die "kubectl logs -c $c failed"
		[[ -z $out ]] || die "the host read the $c container's log"
	done
	show "kubectl exec $POD -c trustee -- true" kc exec "$POD" -c trustee -- true
	[[ $out == *"ExecProcessRequest is blocked by policy"* ]] || die "exec was not blocked by the agent policy"
	show "ls -A <host side of the state volume>" node ls -A "$(host_state_dir "$POD")"
	((rc == 0)) || die "no state volume on the host"
	[[ -z $out ]] || die "the host sees the state volume's contents"
	info "EV-17: pass"
}

# probe <name> <initdata> <want>: run a workload pod and check what it got.
probe() {
	run_probe "$1" "$2" >/dev/null
	show "kubectl get pod $1" kc get pod "$1"
	has_row "$1" 0/1 Completed 0 || die "$1 did not complete"
	show "kubectl logs $1" kc logs "$1"
	[[ $out == "$3" ]] || die "$1 got '$out', want '$3'"
	show_events "$1" "$EVENT_COLUMNS"
	[[ -z $(warnings) ]] || die "Warning events for $1: $(warnings)"
}

ev18() {
	section "EV-18: A CoCo workload gets a key from the unlocked Trustee"
	RESOURCE=$SECRET
	probe workload-ok "$authorized" "$SECRET_VALUE"
	probe workload-other "$unauthorized" DENIED
	info "EV-18: pass"
}

ev19() {
	section "EV-19: Trustee container restarts inside the running CVM"
	local id restarts=0
	id=$(pod "$POD" '{.status.containerStatuses[0].containerID}')
	node crictl stop "${id#containerd://}" >/dev/null || die "could not stop the Trustee container"
	for _ in $(seq 90); do
		restarts=$(pod "$POD" '{.status.containerStatuses[0].restartCount}')
		((restarts >= 1)) && [[ $(ready) == True ]] && break
		sleep 2
	done
	show "kubectl get pod $POD" kc get pod "$POD"
	has_row "$POD" 1/1 Running 1 || die "Trustee did not come back Ready with one restart"
	show "kubectl get pod $POD -o jsonpath='{.status.podIP}'" pod "$POD" '{.status.podIP}'
	[[ $out == "$pod_ip" ]] || die "the pod IP changed from $pod_ip: kubelet made a new sandbox"
	show "kubectl get pod $POD -o jsonpath='{.status.initContainerStatuses[0].restartCount} {.status.initContainerStatuses[0].state.terminated.reason}'" \
		pod "$POD" '{.status.initContainerStatuses[0].restartCount} {.status.initContainerStatuses[0].state.terminated.reason}'
	[[ $out == "0 Completed" ]] || die "the helper ran again: $out"
	show_events "$POD" "TYPE:.type,REASON:.reason,OBJECT:.involvedObject.fieldPath,COUNT:.count,MESSAGE:.message"
	status_refused
	RESOURCE=$SECRET
	run_probe workload-again "$authorized" >/dev/null
	show "kubectl logs workload-again" kc logs workload-again
	[[ $out == "$SECRET_VALUE" ]] || die "after the restart, the workload got '$out'"
	info "EV-19: pass"
}

# deploy_cvm: everything up to where EV-16 starts.
deploy_cvm() {
	setup
	key_id=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["key_id"])' "$work/ceremony/ceremony.json")
	operator_policies
	deploy
	wait_helper
	pod_ip=$(pod "$POD" '{.status.podIP}')
}

# hil_env: $work/hil.env, which makes the commands in the eval docs work in
# an interactive shell, and the EV-18 workload manifests.
hil_env() {
	RESOURCE=$SECRET
	probe_pod workload-ok "$authorized" >"$work/workload-ok.yaml"
	probe_pod workload-other "$unauthorized" >"$work/workload-other.yaml"
	{
		echo "# Source this file. The commands in docs/evals EV-16 to EV-19 then run as written."
		echo "# kubectl and crictl run inside the kind node, so pass manifests on stdin:"
		echo "#   kubectl apply -f - <workload-ok.yaml"
		echo "# Each Security Operator's files: --policy policy-alice --share-file ceremony/alice.share"
		printf 'ENGINE=%q CLUSTER=%q work=%q\n' "$ENGINE" "$CLUSTER" "$work"
		printf 'export ENDPOINT=%q\n' "$endpoint"
		declare -f rootsudo eng node kc tb
		echo 'kubectl() { kc "$@"; }'
		echo 'crictl() { node crictl "$@"; }'
		echo 'trustee-bootstrap() { tb "$@"; }'
		echo 'cd "$work" || return'
	} >"$work/hil.env"
}

main() {
	case ${1:-} in
	'')
		trap cleanup EXIT
		deploy_cvm
		ev16
		ev17
		ev18
		ev19
		info "PASS"
		;;
	hil)
		deploy_cvm
		hil_env
		info "the Trustee CVM is waiting for Shares: EV-16 starts here"
		info "run: source $work/hil.env"
		;;
	*) die "usage: $0 [hil]" ;;
	esac
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
