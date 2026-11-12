#!/usr/bin/env bash
# The evals that need no cluster (docs/evals), for a Linux machine with Go,
# openssl and passwordless sudo:
#
#   ev07   seal refuses a Trustee certificate that names a public host or
#          IP, or that is a CA certificate
#   ev08   the Key Ceremony and seal runbooks leave no secret on disk
#
#   evals-offline.sh [ev07|ev08 ...]   run the named evals, or both
#
# ev08 mounts tmpfs at /mnt/ceremony and /mnt/seal, as the runbooks do, and
# searches the whole root file system: run it on a scratch machine. Prints
# PASS on stderr when every named eval passes. Set E2E_WORK to keep the work
# directory.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=${E2E_WORK:-$(mktemp -d)}
mkdir -p "$work/bin"
info() { echo "[evals-offline] $*" >&2; }
die() { echo "[evals-offline] FAIL: $*" >&2; exit 1; }
tb() { "$work/bin/trustee-bootstrap" "$@"; }

# minimal_tree <dir>: a Trustee config tree that passes sealed-config
# checks 1 to 3, with no TLS pair yet.
minimal_tree() {
	mkdir -p "$1/storage/kbs"
	cp "$repo/deploy/examples/trustee-config/kbs.toml" "$1/"
	echo placeholder >"$1/as-signer.key"
	echo placeholder >"$1/as-signer.crt"
	printf 'package policy\n\ndefault allow := false\n' >"$1/storage/kbs/resource-policy.rego"
}

# tls <dir> <openssl extensions>: Trustee's key and a self-signed certificate.
tls() {
	openssl ecparam -name prime256v1 -genkey -noout -out "$1/tls.key"
	openssl req -new -key "$1/tls.key" -subj "/CN=trustee" |
		openssl x509 -req -signkey "$1/tls.key" -days 2 -out "$1/tls.crt" -extfile <(printf '%s\n' "$2") 2>/dev/null
}

# EV-07: the seal runbook's step 6 with each bad certificate from the eval.
ev07() {
	local ev=$work/ev07 name ext want out
	mkdir -p "$ev/ceremony"
	tb ceremony split --threshold 2 --holders a,b --out-dir "$ev/ceremony" >/dev/null
	while IFS='|' read -r name want ext; do
		minimal_tree "$ev/$name"
		tls "$ev/$name" "$(printf '%b' "$ext")"
		if out=$(tb seal --manifest "$ev/ceremony/ceremony.json" --output "$ev/$name.age" "$ev/$name" 2>&1); then
			[[ $name == control ]] || die "EV-07: seal accepted the $name certificate"
			[[ -s $ev/$name.age ]] || die "EV-07: seal wrote no bundle for the control tree"
		else
			[[ $name != control ]] || die "EV-07: seal refused the control tree: $out"
			[[ $out == *"$want"* ]] || die "EV-07: $name: seal said '$out', want '$want'"
			[[ ! -e $ev/$name.age ]] || die "EV-07: $name: seal refused but wrote a bundle"
		fi
		info "EV-07: $name: ${want:-sealed}"
	done <<-'EOF'
		control||basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:trustee.default.svc.cluster.local
		public-name|names a host outside the cluster|basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:trustee.example.com
		public-ip|names a host outside the cluster|basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:8.8.8.8
		ca|is a CA certificate|basicConstraints=critical,CA:TRUE\nsubjectAltName=DNS:trustee.default.svc.cluster.local
	EOF
	info "EV-07: pass"
}

# as_operator <commands>: an operator types the commands into an
# interactive bash, with Ubuntu's default .bashrc and its own history file.
as_operator() {
	env -i HOME="$home" PATH="$work/bin:/usr/sbin:/usr/bin:/sbin:/bin" TERM=dumb USER="$(id -un)" \
		bash -i <<<"$1" >>"$work/ev08/walk.log" 2>&1
}

# EV-08: walk key-ceremony.md steps 1 to 7 and seal.md steps 1 to 8, then
# search the disk for every secret the walk handled.
ev08() {
	local ev=$work/ev08 canary pattern_file found n
	home=$ev/home
	mkdir -p "$home" "$ev/media"/{alice,bob,carol,manifest} "$ev/outbox"
	cp /etc/skel/.bashrc "$home/"
	printf 'package policy\n\ndefault allow := false\n' >"$ev/resource-policy.rego"
	canary=CANARY-$(openssl rand -hex 16)
	if mountpoint -q /mnt/ceremony || mountpoint -q /mnt/seal; then die "EV-08: /mnt/ceremony or /mnt/seal is already mounted"; fi
	[[ -z $(swapon --show) ]] || info "EV-08: swap is on, which both runbooks forbid; the search covers the disk, not the swap device"

	as_operator "$(
		cat <<-EOF
			sudo mkdir -p /mnt/ceremony
			sudo mount -t tmpfs -o size=1m,mode=0700,uid=\$(id -u) tmpfs /mnt/ceremony
			trustee-bootstrap ceremony split --threshold 2 --holders alice,bob,carol --out-dir /mnt/ceremony
			ls -l /mnt/ceremony
			sha256sum /mnt/ceremony/ceremony.json
			for h in alice bob carol; do echo "sha256:\$(jq -r .share /mnt/ceremony/\$h.share | base64 -d | sha256sum | cut -d' ' -f1)"; jq -r --arg h "\$h" '.shares[] | select(.holder == \$h) | .commitment' /mnt/ceremony/ceremony.json; done
			for h in alice bob carol; do cp --preserve=mode /mnt/ceremony/\$h.share $ev/media/\$h/; done
			cp /mnt/ceremony/ceremony.json $ev/media/manifest/
			sudo umount /mnt/ceremony
		EOF
	)"
	mountpoint -q /mnt/ceremony && die "EV-08: the Key Ceremony left /mnt/ceremony mounted"
	[[ $(stat -c %a "$ev/media/alice/alice.share") == 600 ]] || die "EV-08: the Share file lost its 0600 mode"

	as_operator "$(
		cat <<-EOF
			sudo mkdir -p /mnt/seal
			sudo mount -t tmpfs -o size=8m,mode=0700,uid=\$(id -u) tmpfs /mnt/seal
			cd /mnt/seal
			mkdir -p tree/storage/kbs tree/storage/repository tree/storage/reference_value
			cp $repo/deploy/examples/trustee-config/kbs.toml tree/
			host=trustee.default.svc.cluster.local
			openssl ecparam -name prime256v1 -genkey -noout -out tree/tls.key
			openssl req -new -key tree/tls.key -subj "/CN=\$host" -out tls.csr
			printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "\$host" >tls.ext
			openssl x509 -req -in tls.csr -signkey tree/tls.key -days 365 -extfile tls.ext -out tree/tls.crt
			openssl ecparam -name prime256v1 -genkey -noout -out tree/as-signer.key
			openssl req -x509 -new -key tree/as-signer.key -subj "/CN=Trustee AS signer" -days 365 -out tree/as-signer.crt
			openssl genpkey -algorithm ed25519 | openssl pkey -pubout -out tree/admin.pub
			cp $ev/resource-policy.rego tree/storage/kbs/resource-policy.rego
			read -rs SECRET_VALUE
			$canary
			printf '%s' "\$SECRET_VALUE" >'tree/storage/repository/default\x2Fapp\x2Fsecret'
			unset SECRET_VALUE
			trustee-bootstrap seal --manifest $ev/media/manifest/ceremony.json --output bundle.age tree
			sha256sum bundle.age
			stat -c %s bundle.age
			cp bundle.age tree/tls.crt $ev/outbox/
		EOF
	)"
	# The checker reads the key bodies from the tmpfs before the unmount.
	# The search strings live in /dev/shm, which is memory: sudo can't read
	# a process substitution.
	pattern_file=/dev/shm/evals-offline-patterns
	{
		printf '%s\n' "$canary"
		for h in alice bob carol; do jq -r .share "$ev/media/$h/$h.share"; done
		sed '/-----/d' /mnt/seal/tree/tls.key /mnt/seal/tree/as-signer.key
	} | sed 's/[][\.*^$+?(){}|/]/\\&/g' >"$pattern_file"
	echo 'AGE-SECRET-KEY-1[0-9A-Z]{50}' >>"$pattern_file"
	# Positive control: the search finds each Share where it belongs.
	for h in alice bob carol; do
		grep -qaE -f "$pattern_file" "$ev/media/$h/$h.share" || die "EV-08: the search misses $h's Share in its own file"
	done
	as_operator $'cd /\nsudo umount /mnt/seal'
	mountpoint -q /mnt/seal && die "EV-08: the seal runbook left /mnt/seal mounted"
	[[ -s $ev/outbox/bundle.age && -s $ev/outbox/tls.crt && $(find "$ev/outbox" -type f | wc -l) == 2 ]] ||
		die "EV-08: the outbox should hold bundle.age and tls.crt only"
	# The walk proves something about history only if the shell kept one.
	[[ -s $home/.bash_history ]] || die "EV-08: the operator's shell wrote no history, so the walk tests nothing about it"
	info "EV-08: walked key-ceremony.md steps 1 to 7 and seal.md steps 1 to 8; searching the disk"

	# Every file on the root file system, except the places the runbooks
	# write a Share on purpose, and Go module caches anywhere (container
	# build layers too), which hold age's own test identities. walk.log is
	# what the operator's terminal showed, so it stays in.
	found=$(sudo find / -xdev -type f \
		-not -path "$ev/media/*" -not -path '*/pkg/mod/*' -not -path "$HOME/.cache/go-build/*" -print0 |
		sudo xargs -0 grep -laE -D skip -f "$pattern_file" 2>/dev/null || true)
	n=$(sudo journalctl --no-pager -o cat 2>/dev/null | grep -caE -f "$pattern_file" || true)
	((n == 0)) || found+=$'\n'"the system journal: $n lines"
	n=$(journalctl --user --no-pager -o cat 2>/dev/null | grep -caE -f "$pattern_file" || true)
	((n == 0)) || found+=$'\n'"the user journal: $n lines"
	rm -f "$pattern_file"
	[[ -z $found ]] || die "EV-08: secrets on disk:"$'\n'"$found"
	info "EV-08: no canary, Share, key body or age identity on disk or in the journals"
	info "EV-08: pass"
}

main() {
	local ev evs=("$@")
	((${#evs[@]})) || evs=(ev07 ev08)
	CGO_ENABLED=0 go build -C "$repo" -o "$work/bin/" ./cmd/trustee-bootstrap
	for ev in "${evs[@]}"; do
		case $ev in
		ev07 | ev08) "$ev" ;;
		*) die "usage: $0 [ev07|ev08 ...]" ;;
		esac
	done
	info "PASS"
}

[[ ${BASH_SOURCE[0]} != "$0" ]] || main "$@"
