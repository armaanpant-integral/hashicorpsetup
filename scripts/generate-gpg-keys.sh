#!/usr/bin/env bash
set -euo pipefail

MEMBERS="${1:-10}"
OUT_DIR="${2:-./keys}"
NAME_PREFIX="${3:-vault-member}"

mkdir -p "${OUT_DIR}"

echo "Generating ${MEMBERS} GPG keypairs into: ${OUT_DIR}"
echo "NOTE: This script uses batch mode and expects gpg to be installed."

# If set, used as the secret key passphrase. If empty, keys are generated without a passphrase
# (or with an empty passphrase, depending on your gpg configuration).
GPG_PASSPHRASE="${GPG_PASSPHRASE:-}"

for i in $(seq 1 "${MEMBERS}"); do
  USER_ID="${NAME_PREFIX}-${i} <${NAME_PREFIX}-${i}@local>"

  echo "  - Generating key for: ${USER_ID}"

  # Generate a key (ed25519), non-expiring, using batch mode (if it doesn't exist).
  # --pinentry-mode loopback allows passphrase usage in batch mode.
  if ! gpg --batch --list-keys "${USER_ID}" >/dev/null 2>&1; then
    gpg --batch --yes --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE}" \
      --quick-generate-key "${USER_ID}" ed25519 default never
  fi

  # Resolve fingerprint for the key we will operate on.
  FPR="$(gpg --batch --with-colons --list-keys "${USER_ID}" | awk -F: '$1=="fpr"{print $10; exit}')"
  if [[ -z "${FPR}" ]]; then
    echo "ERROR: could not resolve fingerprint for ${USER_ID}" >&2
    exit 1
  fi

  # Ensure the key has an encryption-capable subkey (cv25519).
  # Some defaults create signing/certification-only keys, which cannot encrypt.
  gpg --batch --yes --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE}" \
    --quick-add-key "${FPR}" cv25519 encr never

  # Export public key (armored)
  gpg --armor --export "${FPR}" > "${OUT_DIR}/member-${i}-public.asc"

  # Export private key (armored). This will include secret key material.
  gpg --armor --export-secret-keys "${FPR}" > "${OUT_DIR}/member-${i}-private.asc"
done

echo "Done."
echo "Public keys:  ${OUT_DIR}/member-*-public.asc"
echo "Private keys: ${OUT_DIR}/member-*-private.asc"

