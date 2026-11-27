#!/bin/sh
# Checks a downloaded Mohur release against a build of its tag:
#   1. denyfirst's release key signed SHA256SUMS;
#   2. the release holds exactly the files on that list, with those hashes;
#   3. the signed list is, byte for byte, the one the build wrote.
#
#   sh scripts/release-verify.sh <release dir> <build dir> [allowed signers]
#
# The build dir is what scripts/release-build.ps1 wrote for the tag. The
# allowed signers default to this checkout's .allowed_signers. The Reproduce
# workflow runs it for every published release, and anyone can run it too.
set -eu

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || { echo "usage: $0 <release dir> <build dir> [allowed signers]" >&2; exit 2; }
release=$1
build=$2
signers=${3:-$(dirname "$0")/../.allowed_signers}

refuse() {
	echo "REFUSED: $*" >&2
	exit 1
}

[ -f "${release}/SHA256SUMS" ] || refuse "the release has no SHA256SUMS."
[ -f "${release}/SHA256SUMS.sig" ] || refuse "the release has no SHA256SUMS.sig."
[ -f "${build}/SHA256SUMS" ] || refuse "${build} holds no build."

# 1. The signature, with the identity and purpose denyfirst signs releases for.
if ! said=$(ssh-keygen -Y verify -f "${signers}" -I releases@denyfirst.dev -n file \
	-s "${release}/SHA256SUMS.sig" <"${release}/SHA256SUMS" 2>&1); then
	echo "${said}" >&2
	refuse "SHA256SUMS is not signed by denyfirst's release key."
fi
echo "${said}"

# 2. Exactly the listed files, each with its hash. A file on the release but
# not on the list would reach people unchecked.
listed=$(awk '{ print $2 }' "${release}/SHA256SUMS" | LC_ALL=C sort)
present=$(cd "${release}" && ls -A | { grep -vx -e SHA256SUMS -e SHA256SUMS.sig || true; } | LC_ALL=C sort)
if [ "${listed}" != "${present}" ]; then
	printf 'On the list:\n%s\nIn the release:\n%s\n' "${listed}" "${present}" >&2
	refuse "the release's files are not the ones on its list."
fi
(cd "${release}" && sha256sum --check --strict --quiet SHA256SUMS) ||
	refuse "a file in the release does not have its listed hash."

# 3. The same bytes as the build of the tag.
if ! cmp -s "${release}/SHA256SUMS" "${build}/SHA256SUMS"; then
	diff -u "${release}/SHA256SUMS" "${build}/SHA256SUMS" >&2 || true
	refuse "the release is not what its tag builds."
fi
echo "OK: the release is signed, complete, and the same bytes its tag builds."
