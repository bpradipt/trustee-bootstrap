#!/usr/bin/env bash
# The scripted negative evals (docs/evals) on the kind + Kata + swtpm cluster
# from kind-kata-swtpm.sh (run its `up` first):
#
#   ev01   the host swaps the Sealed Bundle, before boot and after LOCKED
#   ev11   recreating the Trustee CVM after unlock forgets everything
#   ev15   nothing host-visible holds a secret after a full unlock
#
#   evals.sh [ev01|ev11|ev15 ...]   run the named evals, or all three
#
# One setup serves every eval. The sealed resource is a random canary, so
# EV-15 can search for it. Prints PASS on stderr when all named evals pass.
# Needs what trustee-cvm.sh needs. Set E2E_WORK to choose the work directory.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=golden-path.sh
source "$script_dir/golden-path.sh"
info() { echo "[evals] $*" >&2; }
die() { echo "[evals] FAIL: $*" >&2; exit 1; }

# fresh_pod: a new Trustee CVM from the rendered pod, its helper answering.
fresh_pod() {
	kc delete pod "$POD" --ignore-not-found --wait >/dev/null
	kc apply -f - <"$work/trustee-cvm.yaml" >/dev/null
	endpoint=$(helper_endpoint)
	wait_helper
}

# unlock_pod: Alice and Carol unlock the waiting CVM, and Trustee is Ready.
unlock_pod() {
	approve_ok alice 1
	approve_ok carol 3
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "Trustee did not become Ready"
}

# set_bundle <file>: the host puts <file> in the Sealed Bundle ConfigMap.
set_bundle() {
	kc create configmap trustee-sealed-bundle --from-file=bundle.age=/dev/stdin --dry-run=client -o yaml <"$1" |
		kc apply -f - >/dev/null 2>&1
}

# EV-01: a bundle the host sealed to the same recipient, whose resource
# policy releases everything.
ev01() {
	section "EV-01: Host swaps the Sealed Bundle in a live pod"
	mkdir -p "$work/host-tree"
	cp -r "$work/tree/." "$work/host-tree/"
	printf 'package policy\n\ndefault allow := true\n' >"$work/host-tree/storage/kbs/resource-policy.rego"
	tb seal --manifest "$work/ceremony/ceremony.json" --output "$work/host.age" "$work/host-tree" >/dev/null
	local host_sha256 holder seen=''
	host_sha256=$(sha256sum "$work/host.age" | cut -d' ' -f1)

	set_bundle "$work/host.age"
	fresh_pod
	for holder in alice carol; do
		show "trustee-bootstrap approve ... --share-file $holder.share" approve "$holder"
		if ((rc == 0)) || [[ $out != *"Share not accepted"* ]]; then die "$holder's Share was not refused: $out"; fi
	done
	show_status
	expect_status "$key_id COLLECTING 2 [] [1,3]"
	[[ $(ready) == False && -z $(pod "$POD" '{.status.containerStatuses[0].state.running}') ]] ||
		die "Trustee started on the host's bundle"
	info "EV-01 part 1: with the host's bundle mounted, both Shares were rejected and Trustee never started"

	set_bundle "$work/bundle.age"
	fresh_pod
	# A pod with no agent policy mounts the same ConfigMap and reports
	# what its guest sees, so the eval knows whether a swap reaches a guest.
	kc delete pod bundle-probe --ignore-not-found --wait >/dev/null
	kc apply -f - >/dev/null <<-EOF
		apiVersion: v1
		kind: Pod
		metadata:
		  name: bundle-probe
		spec:
		  runtimeClassName: $RUNTIME_CLASS
		  containers:
		  - name: probe
		    image: $PROBE_IMAGE
		    command: ["sh", "-c", "while true; do sha256sum /b/bundle.age; sleep 5; done"]
		    volumeMounts: [{name: b, mountPath: /b}]
		  volumes:
		  - name: b
		    configMap: {name: trustee-sealed-bundle}
	EOF
	kc wait --for=condition=Ready pod/bundle-probe --timeout=300s >/dev/null || die "bundle-probe did not start"
	set_bundle "$work/host.age"
	for _ in $(seq 40); do
		[[ $(kc logs bundle-probe --tail=1 2>/dev/null) == "$host_sha256"* ]] && seen=yes && break
		sleep 3
	done
	kc delete pod bundle-probe --wait=false >/dev/null
	if [[ -n $seen ]]; then
		info "EV-01 part 2: Kata copied the swapped ConfigMap into a running guest"
	else
		info "EV-01 part 2: Kata did not copy the swapped ConfigMap into a running guest within 120 s, so part 2 shows only that the helper ignores a later swap"
	fi
	unlock_pod
	RESOURCE=$SECRET
	[[ $(run_probe workload-ok "$authorized") == "$SECRET_VALUE" ]] || die "the authorized workload did not get the approved bundle's secret"
	[[ $(run_probe workload-other "$unauthorized") == DENIED ]] ||
		die "the unauthorized workload got a secret: Trustee runs the host's allow-all policy"
	kc delete pod workload-ok workload-other --wait=false >/dev/null
	info "EV-01 part 2: after a swap at COLLECTING, Trustee serves the approved bundle under its sealed policy"
}

# forgotten <previous boot_id>: a new boot that holds nothing of the last one.
forgotten() {
	show_status
	expect_status "$key_id COLLECTING 2 [] []"
	[[ $boot_id != "$1" ]] || die "boot_id did not change"
	[[ $(ready) == False ]] || die "Trustee is Ready without a new Unlock Ceremony"
	# A not-ready pod is listed under notReadyAddresses; only addresses get traffic.
	[[ -z $(kc get endpoints trustee -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null) ]] ||
		die "the trustee Service routes to a CVM that holds no Shares"
	check_host_view
}

ev11() {
	section "EV-11: Pod recreation after unlock forgets everything"
	local uid sandbox pids
	set_bundle "$work/bundle.age"
	fresh_pod
	show_status
	expect_status "$key_id COLLECTING 2 [] []"
	unlock_pod
	local last=$boot_id

	uid=$(pod "$POD" '{.metadata.uid}')
	fresh_pod
	[[ $(pod "$POD" '{.metadata.uid}') != "$uid" ]] || die "the pod was not recreated"
	forgotten "$last"
	info "EV-11 delete: the recreated pod started from LOCKED with a new boot_id and no Shares"
	last=$boot_id
	unlock_pod
	info "EV-11 delete: the existing Operator Policies unlocked the new pod"

	uid=$(pod "$POD" '{.metadata.uid}')
	sandbox=$(node crictl pods --name "^$POD\$" --state ready -q | head -1)
	pids=$(node pgrep -f "qemu.*sandbox-$sandbox") || die "no QEMU process for sandbox $sandbox"
	# shellcheck disable=SC2086 # one PID per word
	node kill -9 $pids
	wait_helper
	[[ $(pod "$POD" '{.metadata.uid}') == "$uid" ]] || die "the pod object changed: this was not a sandbox restart"
	forgotten "$last"
	info "EV-11 QEMU kill: the same pod in a new VM started from LOCKED with a new boot_id and no Shares"
	unlock_pod
	info "EV-11 QEMU kill: the existing Operator Policies unlocked the new VM"
}

# approve_logged <holder> <policy dir>: one approve, its output in $ev.
approve_logged() {
	tb approve --endpoint "$endpoint" --policy "$2" --share-file "$work/ceremony/$1.share" >>"$ev/approve.out" 2>>"$ev/approve.err"
}

# found <surface>: count the search strings in stdin; fail on any. Says how
# many lines it searched, so an empty source can't pass unnoticed.
found() {
	local text n
	text=$(cat)
	n=$(grep -caE -f <(regexes) <<<"$text" || true)
	((n == 0)) || die "EV-15: $1 holds a secret ($n lines)"
	info "EV-15: $1: clean ($(grep -c '' <<<"$text") lines searched)"
}

# regexes: the search strings as extended regexes, in memory only.
regexes() {
	printf '%s\n' "$search" | sed 's/[][\.*^$+?(){}|/]/\\&/g'
	echo 'AGE-SECRET-KEY-1[0-9A-Z]{50}'
}

ev15() {
	section "EV-15: Canary sweep after a full unlock"
	ev=$work/ev15
	mkdir -p "$ev"
	local holder key cid files
	search=$SECRET_VALUE
	for holder in alice bob carol; do
		search+=$'\n'$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["share"])' "$work/ceremony/$holder.share")
	done
	for key in tls.key as-signer.key; do
		search+=$'\n'$(sed '/-----/d' "$work/tree/$key")
	done

	set_bundle "$work/bundle.age"
	fresh_pod
	tb status --endpoint "$endpoint" >>"$ev/status.out"
	# The error paths: a policy that names another bundle, so the helper
	# rejects Bob's Share, and one built from other Init-Data, so his
	# Operator Verifier refuses.
	sed '1i # other Init-Data' "$work/init.toml" >"$ev/init-other.toml"
	tb policy build --init-data "$work/init.toml" --reference-values "$work/rv.json" --accept-tee tpm --allow-untested-profiles \
		--bundle-sha256 "$(printf '0%.0s' $(seq 64))" --manifest "$work/ceremony/ceremony.json" \
		--share-file "$work/ceremony/bob.share" --out-dir "$ev/policy-other-bundle" >/dev/null
	tb policy build --init-data "$ev/init-other.toml" --reference-values "$work/rv.json" --accept-tee tpm --allow-untested-profiles \
		--bundle-sha256 "$bundle_sha256" --manifest "$work/ceremony/ceremony.json" \
		--share-file "$work/ceremony/bob.share" --out-dir "$ev/policy-other-init" >/dev/null
	! approve_logged bob "$ev/policy-other-bundle" || die "EV-15: a Share naming another bundle was accepted"
	! approve_logged bob "$ev/policy-other-init" || die "EV-15: an Operator Verifier released to other Init-Data"
	out=$(tb status --endpoint "$endpoint")
	echo "$out" >>"$ev/status.out"
	expect_status "$key_id COLLECTING 2 [] [2]"
	approve_logged alice "$work/policy-alice" || die "EV-15: alice's approve failed"
	tb status --endpoint "$endpoint" >>"$ev/status.out"
	approve_logged carol "$work/policy-carol" || die "EV-15: carol's approve failed"
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "EV-15: Trustee did not become Ready"
	RESOURCE=$SECRET
	[[ $(run_probe workload-ok "$authorized") == "$SECRET_VALUE" ]] || die "EV-15: the workload did not get the canary"
	cid=$(pod "$POD" '{.status.containerStatuses[0].containerID}')
	node crictl stop "${cid#containerd://}" >/dev/null
	for _ in $(seq 90); do
		[[ $(pod "$POD" '{.status.containerStatuses[0].restartCount}') -ge 1 && $(ready) == True ]] && break
		sleep 2
	done
	[[ $(ready) == True ]] || die "EV-15: Trustee did not come back after its restart"
	info "EV-15: unlocked with both error paths, served the canary, restarted Trustee; searching"

	# Positive controls: the search finds the canary where it belongs, in
	# the workload's own log, through kubectl and on the node's disk.
	[[ $(kc logs workload-ok | grep -caE -f <(regexes) || true) -ge 1 ]] ||
		die "EV-15: the search misses the canary in the workload's log"
	files=$(regexes | node sh -c 'grep -rlaE -D skip -f /dev/stdin /var/log/pods 2>/dev/null' || true)
	[[ $files == */var/log/pods/default_workload-ok_* ]] || die "EV-15: the node search misses the workload's log file"
	info "EV-15: the search finds the canary in the workload's log, through kubectl and on the node"

	kc get all,configmap,secret,event -A -o yaml | found "Kubernetes objects and events"
	# Each kc reads stdin (podman exec -i), so the pod list comes from a
	# file and every kc in the loop reads /dev/null.
	kc get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}' >"$ev/pods"
	while read -r ns name; do
		# The workload prints the secret it fetched; that is its own choice.
		[[ $name == workload-ok ]] && continue
		for c in $(kc get pod -n "$ns" "$name" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' </dev/null); do
			kc logs -n "$ns" "$name" -c "$c" </dev/null 2>/dev/null || true
		done
	done <"$ev/pods" | found "container logs"
	node journalctl --no-pager -o cat | found "the node's journal"
	files=$(regexes | node sh -c 'grep -rlaE -D skip -f /dev/stdin /etc /opt /root /run /tmp /var 2>/dev/null' |
		grep -v '^/var/log/\(pods/default_workload-ok_\|containers/workload-ok_\)' || true)
	[[ -z $files ]] || die "EV-15: files on the node hold a secret: $files"
	info "EV-15: the node's file system: clean"
	{
		cat "$ev/approve.out" "$ev/approve.err"
		cat "$work/audit.log" 2>/dev/null || true
	} | found "approve output and audit records"
	found "status responses" <"$ev/status.out"
	files=$(grep -rlaE -D skip -f <(regexes) "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$HOME/.local/share/containers" 2>/dev/null || true)
	[[ -z $files ]] || die "EV-15: files on the operators' machine hold a secret: $files"
	info "EV-15: the operators' runtime directory and podman storage: clean"
	local journal
	if journal=$(journalctl --user --no-pager -o cat 2>/dev/null); then
		found "the operators' user journal" <<<"$journal"
	else
		info "EV-15: the operators' user journal: not available on this machine"
	fi
	kc delete pod workload-ok --wait=false >/dev/null
}

main() {
	trap 'kc delete pod bundle-probe --ignore-not-found --wait=false >/dev/null 2>&1; cleanup' EXIT
	SECRET_VALUE=CANARY-$(openssl rand -hex 16)
	deploy_cvm >/dev/null
	local ev evs=("$@")
	((${#evs[@]})) || evs=(ev01 ev11 ev15)
	for ev in "${evs[@]}"; do
		case $ev in
		ev01 | ev11 | ev15) "$ev" ;;
		*) die "usage: $0 [ev01|ev11|ev15 ...]" ;;
		esac
	done
	info "PASS"
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
