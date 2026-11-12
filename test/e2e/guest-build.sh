# shellcheck shell=bash
# shellcheck disable=SC2154 # kind-kata-swtpm.sh sets repo, script_dir, src, out and the pins
# The e2e guest artifacts, sourced by kind-kata-swtpm.sh:
#
#   vmlinuz-tpm   the Kata guest kernel with TPM drivers
#   ext/          the coco-extension image, with an AA built with the TPM
#                 attester, and its dm-verity root hash
#   kata/         the shim, guest image and config from the kata-static
#                 tarball
#
# .github/workflows/e2e-guest.yml packs them into one image, tagged with the
# sha256 of the files that decide what they hold. `up` pulls that tag, and
# builds the files only when the registry doesn't have it.

GUEST_IMAGE=${E2E_GUEST_IMAGE:-ghcr.io/confidential-devhub/trustee-bootstrap-e2e-guest}

# guest_tag: the image tag for the current pins and build steps.
guest_tag() {
	cat "$repo/versions.yaml" "$script_dir/guest-build.sh" "$script_dir/kernel-tpm.conf" | sha256sum | cut -d' ' -f1
}

# guest: the guest artifacts for guest_tag in $out, pulled or built. A stamp
# records the tag, so files built for other pins get replaced.
guest() {
	local tag
	tag=$(guest_tag)
	[[ $(cat "$out/guest.tag" 2>/dev/null) == "$tag" ]] && return
	sudo rm -rf "$out/vmlinuz-tpm" "$out/aa" "$out/ext" "$out/kata" "$out/guest.tag"
	mkdir -p "$out"
	if eng pull -q "$GUEST_IMAGE:$tag" >/dev/null 2>&1; then
		info "using $GUEST_IMAGE:$tag"
		# shellcheck disable=SC2016 # expands in the container
		eng run --rm -v "$out:/out" -e OWNER="$(id -u):$(id -g)" "$GUEST_IMAGE:$tag" \
			sh -c 'cp -a /e2e-guest/. /out/ && chown -R "$OWNER" /out'
		eng rmi "$GUEST_IMAGE:$tag" >/dev/null || true
	else
		info "no $GUEST_IMAGE:$tag: building the guest artifacts"
		build_deps
		build_kernel
		build_extension
		build_kata
	fi
	echo "$tag" >"$out/guest.tag"
}

# publish: push the guest image for guest_tag, unless the registry has it.
# The e2e-guest workflow runs it after logging in to ghcr.io.
publish() {
	local ref
	ref=$GUEST_IMAGE:$(guest_tag)
	if eng pull -q "$ref" >/dev/null 2>&1; then
		info "$ref exists"
		return
	fi
	guest
	printf 'FROM %s\nLABEL org.opencontainers.image.source=https://github.com/confidential-devhub/trustee-bootstrap\nCOPY vmlinuz-tpm /e2e-guest/\nCOPY ext /e2e-guest/ext\nCOPY kata /e2e-guest/kata\n' \
		"$PROBE_IMAGE" >"$E2E_CACHE/Containerfile.guest"
	eng build -q -f "$E2E_CACHE/Containerfile.guest" -t "$ref" "$out" >/dev/null
	eng push -q "$ref"
	eng rmi "$ref" >/dev/null || true
	info "pushed $ref"
}

# build_deps: the host packages that the builds below need.
build_deps() {
	command -v apt-get >/dev/null || die "install the build tools by hand (see build_deps)"
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
		bc bison build-essential cpio cryptsetup-bin curl erofs-utils flex git kmod \
		libelf-dev libssl-dev parted patch python3 rsync zstd >/dev/null
}

# clone_at <url> <tag> <commit> <dir> [sparse paths...]
clone_at() {
	local url=$1 tag=$2 commit=$3 dir=$4
	shift 4
	if [[ ! -d $dir/.git ]]; then
		git clone -q --depth 1 --branch "$tag" --filter=blob:none ${1:+--sparse} "$url" "$dir" 2>/dev/null
		[[ $# -eq 0 ]] || git -C "$dir" sparse-checkout set --skip-checks "$@"
	fi
	[[ $(git -C "$dir" rev-parse HEAD) == "$commit" ]] || die "$dir is not at $commit"
}

# The Kata 4.2.0 guest kernel has no TPM driver. Rebuild it with Kata's own
# build-kernel.sh and fragments (same flags as kata-deploy-binaries.sh
# install_kernel on x86_64), plus kernel-tpm.conf.
build_kernel() {
	[[ -f $out/vmlinuz-tpm ]] && return
	info "building the Kata guest kernel with TPM drivers"
	clone_at https://github.com/kata-containers/kata-containers "$KATA_TAG" "$KATA_COMMIT" \
		"$src/kata" tools/packaging/kernel tools/packaging/scripts
	cp "$script_dir/kernel-tpm.conf" "$src/kata/tools/packaging/kernel/configs/fragments/x86_64/tpm.conf"
	local b=$E2E_CACHE/kernel-build kb="$src/kata/tools/packaging/kernel/build-kernel.sh"
	local args=(-a x86_64 -v "$KERNEL_VERSION" -u https://cdn.kernel.org/pub/linux/kernel/v6.x/ -x -m)
	mkdir -p "$b" "$out"
	(cd "$b" && "$kb" "${args[@]}" -f setup && "$kb" "${args[@]}" build)
	grep -q '^CONFIG_TCG_CRB=y' "$b"/kata-linux-*/.config || die "TPM drivers missing from kernel config"
	cp "$b"/kata-linux-*/arch/x86/boot/bzImage "$out/vmlinuz-tpm"
	rm -rf "$b"
}

# The stock coco-extension AA is built with snp and tdx attesters only. Build
# the pinned AA with tpm-attester on the guest's Ubuntu release, and keep its
# non-glibc libraries (tss2, openssl) next to it, as assemble-rootfs.sh does
# for the NVIDIA variant. Everything except the outputs stays in the
# container.
build_aa() {
	[[ -f $out/aa/attestation-agent ]] && return
	info "building attestation-agent with tpm-attester"
	clone_at https://github.com/confidential-containers/guest-components "$GC_TAG" "$GC_COMMIT" "$src/gc"
	mkdir -p "$out/aa"
	# shellcheck disable=SC2016 # expands in the container
	eng run --rm -v "$src/gc:/src:ro" -v "$out/aa:/out" -e RUST_TOOLCHAIN="$RUST_TOOLCHAIN" \
		-e OWNER="$(id -u):$(id -g)" "$BUILDER_IMAGE" bash -euo pipefail -c '
		export DEBIAN_FRONTEND=noninteractive PATH=/root/.cargo/bin:$PATH
		apt-get update -qq
		apt-get install -y -qq --no-install-recommends ca-certificates clang cmake curl g++ gcc \
			libclang-dev libssl-dev libtss2-dev make perl pkg-config protobuf-compiler >/dev/null
		curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
		cp -a /src /build
		make -C /build/attestation-agent ttrpc=true ATTESTER=tpm-attester
		aa=/build/target/x86_64-unknown-linux-gnu/release/attestation-agent
		strip "$aa"
		install -D -m0755 "$aa" /out/attestation-agent
		{ ldd "$aa"; echo "/usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0 x"; } |
			grep -o "/[^ ]*" | while read -r lib; do
				case ${lib##*/} in ld-linux-* | libc.so.* | libdl.so.* | libm.so.* | libpthread.so.* | librt.so.*) continue ;; esac
				install -D -m0755 "$lib" "/out/lib/${lib##*/}"
			done
		chown -R "$OWNER" /out'
	eng rmi "$BUILDER_IMAGE" >/dev/null || true
}

# The pinned coco-extension payload with the AA swapped for build_aa's, packed
# into a dm-verity extension image by guest-components' own script.
build_extension() {
	[[ -f $out/ext/kata-containers-coco-extension.img ]] && return
	build_aa
	info "building the coco extension image with the tpm AA"
	local root=$E2E_CACHE/ext-rootfs c
	sudo rm -rf "$root" && mkdir -p "$root"
	c=$(eng create "$COCO_EXTENSION_IMAGE" /x)
	eng export "$c" | sudo tar -x -C "$root"
	eng rm "$c" >/dev/null
	eng rmi "$COCO_EXTENSION_IMAGE" >/dev/null || true
	sudo install -m0755 "$out/aa/attestation-agent" "$root/usr/local/bin/attestation-agent"
	sudo install -m0755 -D -t "$root/usr/local/lib" "$out/aa/lib/"*
	local manifest=$root/etc/kata-extensions/components.toml
	grep -q '^  path = "usr/local/bin/attestation-agent"$' "$manifest" || die "unexpected $manifest"
	sudo sed -i '/^  path = "usr\/local\/bin\/attestation-agent"$/a\  env  = { LD_LIBRARY_PATH = "${extension_root}/usr/local/lib" }' "$manifest"
	ROOTFS_DIR=$root OUTPUT_DIR=$out/ext "$src/gc/tools/coco-extension/build-erofs-image.sh"
	sudo rm -rf "$root"
}

# Only the runtime-rs shim, the base guest image and the coco-dev config come
# from the pinned kata-static tarball; its QEMU is built without TPM support.
build_kata() {
	[[ -f $out/kata/containerd-shim-kata-v2 ]] && return
	info "extracting Kata $KATA_TAG"
	local tarball=$E2E_CACHE/kata-static-$KATA_TAG-amd64.tar.zst
	curl -fsSLo "$tarball" "https://github.com/kata-containers/kata-containers/releases/download/$KATA_TAG/kata-static-$KATA_TAG-amd64.tar.zst"
	echo "$KATA_STATIC_SHA256  $tarball" | sha256sum -c --quiet
	mkdir -p "$out/kata"
	tar --zstd -xf "$tarball" -C "$out/kata" --transform='s|.*/||' \
		./opt/kata/share/kata-containers/kata-ubuntu-resolute.image \
		./opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-coco-dev-runtime-rs.toml \
		./opt/kata/runtime-rs/bin/containerd-shim-kata-v2
	rm -f "$tarball"
}
