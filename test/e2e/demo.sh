#!/usr/bin/env bash
# A recorded walk through one Unlock Ceremony, for the README: the Key
# Ceremony, sealing, the Trustee CVM, two Security Operators' approvals and
# a workload that gets its key. Each prompt names who runs the step. Runs on
# the kind + Kata + swtpm cluster from kind-kata-swtpm.sh (run its `up`
# first).
#
#   demo.sh record FILE.cast   prepare off camera (the registry, the helper
#                              image, genpolicy, Trustee's plaintext tree),
#                              then record the walk with asciinema
#   demo.sh scene              the walk itself; `record` runs it
#
# Turn the recording into the README's GIF with agg:
#   agg --idle-time-limit 2 FILE.cast docs/demo/unlock-ceremony.gif
#
# Needs what trustee-cvm.sh needs, plus asciinema. Leaves the cluster
# objects in place.
# shellcheck disable=SC2016,SC2034 # the walk shows commands unexpanded; eval reads their variables
set -euo pipefail

export E2E_WORK=${E2E_WORK:-$(mktemp -d)}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=trustee-cvm.sh
source "$script_dir/trustee-cvm.sh"
info() { echo "[demo] $*" >&2; }
die() { echo "[demo] FAIL: $*" >&2; exit 1; }

# prep: everything that is plumbing, not part of the story.
prep() {
	prepare
	mkdir -p "$work/bin"
	CGO_ENABLED=0 "$GO" build -C "$repo" -o "$work/bin/" ./cmd/trustee-bootstrap
	trustee_tree
	cvm_initdata
	cp "$examples/trustee-cvm.yaml" "$work/pod.yaml"
	printf '%s\n' "$authorized" >"$work/workload-ok.toml"
	printf '%s\n' "$unauthorized" >"$work/workload-other.toml"
	RESOURCE=$SECRET
	probe_pod workload-ok "$authorized" >"$work/workload-ok.yaml"
	probe_pod workload-other "$unauthorized" >"$work/workload-other.yaml"
	rm -rf "$work/ceremony" "$work/bundle.age" "$work"/policy-* "$work"/*-audit.log
	# The Key Ceremony runbook mounts a tmpfs here; ceremony split writes into it.
	mkdir -m 0700 "$work/ceremony"
	printf 'helper_image=%q registry=%q gp=%q\n' "$helper_image" "$registry" "$gp" >"$work/demo.env"
}

# say <text>: narration.
say() {
	printf '\n\033[1;36m# %s\033[0m\n' "$*"
	sleep 2
}

# as <role>: whose prompt the next commands show.
as() { role=$1; }

# run <command> [may-fail]: type the command at the role's prompt, then run
# it. A failed step ends the recording, unless it may fail.
run() {
	local i
	printf '\033[1;32m%s$\033[0m ' "$role"
	for ((i = 0; i < ${#1}; i++)); do
		printf '%s' "${1:i:1}"
		sleep 0.012
	done
	printf '\n'
	eval "$1" || [[ ${2:-} == may-fail ]] || die "step failed: $1"
	sleep 1.5
}

scene() {
	# shellcheck source=/dev/null
	source "$work/demo.env"
	GP=$gp REGISTRY=$registry HELPER_IMAGE=$helper_image
	kubectl() { kc "$@"; }
	trustee-bootstrap() { tb "$@"; }
	genpolicy() { "$GP/genpolicy" "$@"; }
	cd "$work"
	clear
	printf '\033[1mtrustee-bootstrap: 2 of 3 Security Operators unlock Trustee in a confidential VM\033[0m\n'
	printf 'kind + Kata + swtpm. Each prompt names who runs the step.\n'
	sleep 3

	say "1. Key Ceremony, air-gapped: split a new age key into 3 Shares, any 2 unlock"
	as ceremony-authority
	run 'trustee-bootstrap ceremony split --threshold 2 --holders alice,bob,carol \
    --out-dir ceremony'
	run 'ls -l ceremony'
	say "The Ceremony Manifest is public. The Trustee CVM pins its SHA-256."
	run 'jq "del(.shares)" ceremony/ceremony.json'
	run 'jq -c ".shares[]" ceremony/ceremony.json'
	say "One Share file per Security Operator. The private key never touched a disk."
	run "jq '.share |= .[:16] + \"...\"' ceremony/alice.share"

	say "2. Seal Trustee's whole config to the ceremony's public key"
	as infra-operator
	run 'find tree -type f | sort'
	say "The sealed resource policy releases the secret only to one workload's Init-Data"
	run 'grep -v "^#" tree/storage/kbs/resource-policy.rego'
	run 'trustee-bootstrap seal --manifest ceremony/ceremony.json --output bundle.age tree'
	BUNDLE_SHA256=$(sha256sum bundle.age | cut -d' ' -f1)
	run 'rm -r tree'
	say "The plaintext is gone. The cluster gets bundle.age; operators get its digest."

	say "3. Deploy the Trustee CVM: one Kata pod, the Bootstrap Helper as its init container"
	run 'MANIFEST_SHA256=$(sha256sum ceremony/ceremony.json | cut -d" " -f1)'
	run 'sed "s|@HELPER_IMAGE@|$HELPER_IMAGE|; s|@MANIFEST_SHA256@|$MANIFEST_SHA256|" \
    pod.yaml >trustee-cvm.yaml'
	run 'grep -nE "runtimeClassName|image:|--manifest-sha256|--out=|medium" trustee-cvm.yaml'
	say "genpolicy writes a Kata Agent policy into the Init-Data: pinned images and args, no exec"
	run 'genpolicy -y trustee-cvm.yaml -p "$GP/rules.rego" -j "$GP" \
    --initdata-path=init-data.toml --insecure-registry="$REGISTRY" >/dev/null'
	run 'kubectl create configmap trustee-ceremony-manifest \
    --from-file=ceremony.json=/dev/stdin <ceremony/ceremony.json'
	run 'kubectl create configmap trustee-sealed-bundle \
    --from-file=bundle.age=/dev/stdin <bundle.age'
	run 'kubectl apply -f - <trustee-cvm.yaml'
	ENDPOINT=$(helper_endpoint)
	endpoint=$ENDPOINT
	wait_helper
	run 'kubectl get pod trustee-cvm'
	extract_initdata

	say "4. Each Security Operator reviews the measured Init-Data and builds an Operator Policy"
	as alice
	run 'sha256sum ceremony/ceremony.json'
	run "grep -o -- '--manifest-sha256=[0-9a-f]*' init.toml | sort -u"
	run "grep -n 'default ExecProcessRequest\\|default ReadStreamRequest' init.toml"
	run 'trustee-bootstrap policy build --init-data init.toml --reference-values rv.json \
    --accept-tee tpm --allow-untested-profiles --bundle-sha256 "$BUNDLE_SHA256" \
    --manifest ceremony/ceremony.json --share-file ceremony/alice.share --out-dir policy-alice'
	as carol
	run 'trustee-bootstrap policy build --init-data init.toml --reference-values rv.json \
    --accept-tee tpm --allow-untested-profiles --bundle-sha256 "$BUNDLE_SHA256" \
    --manifest ceremony/ceremony.json --share-file ceremony/carol.share --out-dir policy-carol'
	say "Same digest: both reviewed the same Init-Data. swtpm is for testing, never production."

	say "5. Unlock Ceremony: each approve attests the CVM, then releases one Share to it"
	as alice
	run 'trustee-bootstrap status --endpoint "$ENDPOINT"'
	run 'trustee-bootstrap approve --endpoint "$ENDPOINT" --policy policy-alice \
    --share-file ceremony/alice.share 2>>alice-audit.log'
	run 'trustee-bootstrap status --endpoint "$ENDPOINT" | jq -c "{state, accepted}"'
	as carol
	run 'trustee-bootstrap approve --endpoint "$ENDPOINT" --policy policy-carol \
    --share-file ceremony/carol.share 2>>carol-audit.log'
	say "2 of 3: the helper rebuilt the key, unsealed into guest memory and exited"
	as infra-operator
	run 'kubectl wait --for=condition=Ready pod/trustee-cvm --timeout=600s'
	run 'kubectl get pod trustee-cvm'

	say "The host runs the pod but can't look inside"
	as host
	run "kubectl exec trustee-cvm -c trustee -- cat /trustee/config/tls.key 2>&1 |
    grep -o 'ExecProcessRequest is blocked by policy'" may-fail
	run 'kubectl logs trustee-cvm -c trustee | wc -c'

	say "6. A workload pins Trustee's certificate in its own Init-Data and asks for its secret"
	as workload-owner
	run 'head -12 workload-ok.toml'
	say "The pod carries that file, gzip + base64, in its cc_init_data annotation"
	run "sed -E 's/(cc_init_data: \").*/\\1...\"/' workload-ok.yaml"
	run 'kubectl apply -f - <workload-ok.yaml'
	run "kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/workload-ok \\
    --timeout=300s"
	run 'kubectl logs workload-ok'
	say "Other Init-Data, no secret: Trustee enforces the sealed policy"
	run 'diff workload-ok.toml workload-other.toml' may-fail
	run 'kubectl apply -f - <workload-other.yaml'
	run "kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/workload-other \\
    --timeout=300s"
	run 'kubectl logs workload-other'

	say "Done. A new pod means new guest memory, and a new Unlock Ceremony."
	sleep 4
}

main() {
	case ${1:-} in
	record)
		[[ -n ${2:-} ]] || die "usage: $0 record FILE.cast"
		prep
		info "recording"
		asciinema rec --overwrite --cols 100 --rows 32 --idle-time-limit 2 \
			--title "trustee-bootstrap: an Unlock Ceremony" --command "$0 scene" "$2"
		;;
	scene) scene ;;
	*) die "usage: $0 record FILE.cast" ;;
	esac
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
