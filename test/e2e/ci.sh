#!/usr/bin/env bash
# The checks CI runs on every pull request (.github/workflows/ci.yml). Run
# the same command here to get the same result.
#
#   ci.sh go          go vet and go test
#   ci.sh lint BASE   the Go gate's checks, with its pinned tools and
#                     limits, on the changes since BASE
#   ci.sh release DIR [VERSION]
#                     the release binaries, a CycloneDX SBOM for each and
#                     SHA256SUMS, written into DIR
#   ci.sh e2e         the claim-profile fixtures through the pinned KBS
#                     image (test/e2e/profiles), then the swtpm end-to-end
#                     tests: kind-kata-swtpm.sh up, share-release.sh and
#                     trustee-cvm.sh, then down
#   ci.sh needs-e2e BASE
#                     prints e2e=false when every file changed since BASE
#                     is documentation (docs/, .scratch/ or *.md), and
#                     e2e=true otherwise
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
# The SBOM tool. go run fetches this exact version, and the Go checksum
# database verifies its source and every dependency.
CYCLONEDX_GOMOD=github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
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

# needs_e2e <base>: a documentation-only change skips the e2e job. An empty
# diff or a diff that fails runs it, so the skip can't hide a code change.
needs_e2e() {
	local files
	if ! files=$(git diff --name-only "$1" HEAD) || [[ -z $files ]]; then
		echo e2e=true
	elif printf '%s\n' "$files" | grep -qvE '^(docs/|\.scratch/)|\.md$'; then
		echo e2e=true
	else
		echo e2e=false
	fi
}

# release <dir> [version]: build each binary as the helper image does, then
# describe it with an SBOM read from the module data the binary carries.
release() {
	local out=$1 version=${2:-$(git describe --tags --always --dirty 2>/dev/null || echo devel)} bin
	mkdir -p "$out"
	for bin in trustee-bootstrap bootstrap-helper; do
		CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$out/$bin" "./cmd/$bin"
		go run "$CYCLONEDX_GOMOD" bin -json -version "$version" -output "$out/$bin.cdx.json" "$out/$bin"
	done
	(cd "$out" && sha256sum trustee-bootstrap bootstrap-helper trustee-bootstrap.cdx.json bootstrap-helper.cdx.json >SHA256SUMS)
}

case "${1:-}" in
go)
	# go.mod and go.sum pin every dependency: fail if either is stale, or
	# if a downloaded module differs from its go.sum hash.
	go mod tidy -diff
	go mod verify
	go vet ./...
	go test ./...
	;;
release) release "${2:?usage: $0 release DIR [VERSION]}" "${3:-}" ;;
lint) lint "${2:?usage: $0 lint BASE}" ;;
needs-e2e) needs_e2e "${2:?usage: $0 needs-e2e BASE}" ;;
e2e)
	# trustee-cvm.sh builds the helper image with podman.
	export E2E_ENGINE=podman
	# The Operator Verifier runs on rootless podman, which keeps its crun
	# state here. Show the owner, so a root-owned leftover is easy to spot.
	ls -ld "${XDG_RUNTIME_DIR:-/nonexistent}" "${XDG_RUNTIME_DIR:-/nonexistent}/crun" || true
	# AT-28: only the matching evidence fixtures get a release.
	go test -count=1 ./test/e2e/profiles -args -engine podman
	trap '"$e2e/kind-kata-swtpm.sh" down' EXIT
	"$e2e/kind-kata-swtpm.sh" up
	"$e2e/share-release.sh"
	"$e2e/trustee-cvm.sh"
	;;
*)
	echo "usage: $0 go | lint BASE | release DIR [VERSION] | e2e | needs-e2e BASE" >&2
	exit 2
	;;
esac
