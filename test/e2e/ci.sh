#!/usr/bin/env bash
# The checks CI runs on every pull request (.github/workflows/ci.yml). Run
# the same command here to get the same result.
#
#   ci.sh go          go vet and go test
#   ci.sh lint BASE   the Go gate's checks, with its pinned tools and
#                     limits, on the changes since BASE
#   ci.sh e2e         the swtpm end-to-end tests: kind-kata-swtpm.sh up,
#                     share-release.sh and trustee-cvm.sh, then down
#
# e2e needs what kind-kata-swtpm.sh needs: /dev/kvm, sudo, apt-get, rootful
# podman, about 8 GB of disk and network access. A cold run builds for about
# 20 minutes; the build outputs are in $E2E_CACHE/out.
set -euo pipefail

e2e=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$e2e/../.."

# The tools the Go gate installs, with the sha256s it checks.
GOLANGCI_LINT_URL=https://github.com/golangci/golangci-lint/releases/download/v2.12.2/golangci-lint-2.12.2-linux-amd64.tar.gz
GOLANGCI_LINT_SHA256=8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553
GREMLINS_URL=https://github.com/go-gremlins/gremlins/releases/download/v0.6.0/gremlins_0.6.0_linux_amd64.tar.gz
GREMLINS_SHA256=b02a42e47935f891c9a411d68c07e211c7082609e79c2435b67c85ee9658c538
JSCPD_URL=https://github.com/kucherenko/jscpd/releases/download/v5.4.2/jscpd-linux-x64-musl.tar.gz
JSCPD_SHA256=5f18a6b70b4210782fc3c401c780ba994a2777249cd44d97d6fa460f6fff4570
tools=${LINT_TOOLS:-${XDG_CACHE_HOME:-$HOME/.cache}/trustee-bootstrap-lint}

# tool <name> <url> <sha256>: unpack a pinned release into $tools/<name> once.
tool() {
	local dir=$tools/$1
	[[ -d $dir ]] && return
	mkdir -p "$tools" "$dir.tmp"
	curl -fsSLo "$dir.tar.gz" "$2"
	echo "$3  $dir.tar.gz" | sha256sum -c --quiet
	tar -xzf "$dir.tar.gz" -C "$dir.tmp"
	rm "$dir.tar.gz"
	mv "$dir.tmp" "$dir"
}

# lint <base>: the Go gate on the changes since <base>.
lint() {
	local base out rc=0
	base=$(git merge-base HEAD "$1")
	tool golangci-lint "$GOLANGCI_LINT_URL" "$GOLANGCI_LINT_SHA256"
	tool gremlins "$GREMLINS_URL" "$GREMLINS_SHA256"
	tool jscpd "$JSCPD_URL" "$JSCPD_SHA256"

	echo "== complexity and length (golangci-lint)"
	"$tools/golangci-lint/golangci-lint-2.12.2-linux-amd64/golangci-lint" run -c .golangci.yml \
		--new-from-rev="$base" --whole-files ./...

	echo "== mutation testing (gremlins)"
	if [[ -n $(git diff --name-only --diff-filter=d "$base" -- '*.go' ':!*_test.go') ]]; then
		out=$("$tools/gremlins/gremlins" unleash --diff "$base" --workers 3 --timeout-coefficient 20) || rc=$?
		grep -E 'LIVED|NOT COVERED|Killed:|Timed out:|efficacy|coverage:' <<<"$out" || echo "$out"
		if ((rc != 0)); then
			echo "FAIL: gremlins exited $rc" >&2
			return 1
		fi
		if grep -qE '^ *(LIVED|NOT COVERED)' <<<"$out"; then
			echo "FAIL: gremlins: surviving or uncovered mutants" >&2
			return 1
		fi
	else
		echo "no changed Go source files"
	fi

	echo "== duplication (jscpd)"
	"$tools/jscpd/jscpd" --format go --baseline-from-ref "$base" --fail-on-new-clones \
		--ignore '**/*_test.go,**/tests/**,**/testdata/**,**/target/**,**/vendor/**' --reporters console .
}

case "${1:-}" in
go)
	go vet ./...
	go test ./...
	;;
lint) lint "${2:?usage: $0 lint BASE}" ;;
e2e)
	# trustee-cvm.sh builds the helper image with podman.
	export E2E_ENGINE=podman
	trap '"$e2e/kind-kata-swtpm.sh" down' EXIT
	"$e2e/kind-kata-swtpm.sh" up
	"$e2e/share-release.sh"
	"$e2e/trustee-cvm.sh"
	;;
*)
	echo "usage: $0 go | lint BASE | e2e" >&2
	exit 2
	;;
esac
