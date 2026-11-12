# What the Security Operators run in the e2e tests: share-release.sh and
# trustee-cvm.sh source this file. Callers set $work (the work directory,
# with bin/trustee-bootstrap, ceremony/, init.toml and rv.json),
# $bundle_sha256 and $endpoint, and define die.
# shellcheck shell=bash
# shellcheck disable=SC2154 # the sourcing script sets work, bundle_sha256 and endpoint

tb() { "$work/bin/trustee-bootstrap" "$@"; }

# policy_build <holder> [out dir]: the Security Operator reviews init.toml
# and builds their Operator Policy from it. Prints the Init-Data digest it
# computed. For another bundle, Init-Data or Key Ceremony, set
# bundle_sha256, init_toml or ceremony_dir in a subshell.
policy_build() {
	local c=${ceremony_dir:-$work/ceremony}
	tb policy build --init-data "${init_toml:-$work/init.toml}" --reference-values "$work/rv.json" --accept-tee tpm --allow-untested-profiles \
		--bundle-sha256 "$bundle_sha256" --manifest "$c/ceremony.json" \
		--share-file "$c/$1.share" --out-dir "${2:-$work/policy-$1}"
}

# status_is <state accepted>, e.g. status_is "PUBLISHED [1, 3]"
status_is() {
	local got
	got=$(tb status --endpoint "$endpoint" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["state"], s["accepted"])')
	[[ $got == "$1" ]] || die "status is '$got', want '$1'"
}

# approve_via <endpoint> <holder> [flags...]: prints "accepted", or the
# error output on failure. Its audit records go to $work/audit.log.
approve_via() {
	local to=$1 holder=$2 rc=0
	shift 2
	tb approve --endpoint "$to" --policy "$work/policy-$holder" \
		--share-file "$work/ceremony/$holder.share" "$@" 2>"$work/approve.err" || rc=$?
	cat "$work/approve.err" >>"$work/audit.log"
	((rc == 0)) || cat "$work/approve.err"
	return "$rc"
}

# approve <holder> [flags...]: through the Bootstrap Helper at $endpoint.
approve() { approve_via "$endpoint" "$@"; }
