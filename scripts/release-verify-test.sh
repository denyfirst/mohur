#!/bin/sh
# Shows that release-verify.sh accepts a good release and refuses each way a
# release can be wrong. A throwaway key stands in for denyfirst's.
#
#   sh scripts/release-verify-test.sh <build dir from release-build.ps1>
set -eu

build=$1
verify="$(dirname "$0")/release-verify.sh"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
ssh-keygen -q -t ed25519 -N '' -C test -f "${tmp}/key"
ssh-keygen -q -t ed25519 -N '' -C other -f "${tmp}/other"
printf 'releases@denyfirst.dev namespaces="file" %s\n' "$(cat "${tmp}/key.pub")" >"${tmp}/signers"
rel="${tmp}/release"
amd64=$(cd "${build}" && ls mohurd_*_linux_amd64)
arm64=$(cd "${build}" && ls mohurd_*_linux_arm64)

# A fresh copy of the build as a release, signed with the given key and
# purpose (the test key, for files, by default).
release() {
	rm -rf "${rel}"
	mkdir "${rel}"
	cp "${build}/${amd64}" "${build}/${arm64}" "${build}/SHA256SUMS" "${rel}/"
}
sign() {
	rm -f "${rel}/SHA256SUMS.sig"
	ssh-keygen -q -Y sign -f "${1:-${tmp}/key}" -n "${2:-file}" "${rel}/SHA256SUMS" 2>/dev/null
}
# The list as release-build.ps1 writes it, for files changed after the build.
relist() {
	for f in "${amd64}" "${arm64}"; do
		printf '%s  %s\n' "$(sha256sum <"${rel}/${f}" | cut -d' ' -f1)" "${f}"
	done >"${rel}/SHA256SUMS"
}

failed=0
expect() {
	if sh "${verify}" "${rel}" "${build}" "${tmp}/signers" >"${tmp}/said" 2>&1; then got=accepted; else got=refused; fi
	if [ "${got}" = "$1" ]; then
		echo "ok    $1: $2"
		sed -n 's/^REFUSED: /        /p' "${tmp}/said"
	else
		echo "WRONG $got: $2"
		sed 's/^/      /' "${tmp}/said"
		failed=1
	fi
}

release; sign
expect accepted "a signed release that its tag builds"

release
expect refused "no signature"

release; sign "${tmp}/other"
expect refused "signed by a key that is not denyfirst's"

release; sign "${tmp}/key" git
expect refused "signed by denyfirst's key for something other than files"

release; sign; printf 'x' | dd of="${rel}/${amd64}" bs=1 seek=4096 conv=notrunc 2>/dev/null
expect refused "a file changed after signing"

release; printf 'x' >>"${rel}/${arm64}"; relist; sign
expect refused "a signed list of files that are not what the tag builds"

release; sign; cp "${build}/${amd64}" "${rel}/mohurd"
expect refused "a file on the release that is not on the list"

release; sign; rm "${rel}/${arm64}"
expect refused "a listed file missing from the release"

release; sign; rm "${rel}/${amd64}" "${rel}/${arm64}"
expect refused "a signed list with none of its files"

[ "${failed}" -eq 0 ] || { echo "release-verify.sh answered wrongly" >&2; exit 1; }
echo "release-verify.sh answered every case rightly."
