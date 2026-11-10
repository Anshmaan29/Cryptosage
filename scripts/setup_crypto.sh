#!/usr/bin/env bash
# Reproducible native liboqs build; Linux/macOS, Python 3.12+, compiler and Git required.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON=${PYTHON:-python3}
"$PYTHON" -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ is required"'
command -v git >/dev/null
command -v cc >/dev/null
[ -d "$ROOT/.venv" ] || "$PYTHON" -m venv "$ROOT/.venv"
export PATH="$ROOT/.venv/bin:$PATH"
export PIP_CACHE_DIR="$ROOT/.build/pip-cache"
export OQS_INSTALL_PATH="$ROOT/.local"
mkdir -p "$ROOT/.build"
python -m pip install 'pip==26.3'
python -m pip install 'cmake==4.4.4' 'ninja==1.13.2' 'cryptography==50.0.2'

checkout_release() {
  local repo="$1" tag="$2" sha="$3" destination="$4"
  if [ ! -d "$destination" ]; then
    git clone --depth 1 --branch "$tag" "https://github.com/open-quantum-safe/$repo.git" "$destination"
  fi
  if [ "$(git -C "$destination" rev-parse HEAD)" != "$sha" ]; then
    echo "Refusing unexpected source revision in $destination; preserve it and use a clean .build directory." >&2
    exit 1
  fi
  if [ -n "$(git -C "$destination" status --porcelain --untracked-files=no)" ]; then
    echo "Refusing modified cryptographic source in $destination." >&2
    exit 1
  fi
}
checkout_release liboqs 0.16.0 5a1a854b0dc9f2141bdc771c555ee60c37950183 "$ROOT/.build/liboqs"
checkout_release liboqs-python 0.16.0.2 64c76ad0a80d6c69f2003219eb27b253782a3d68 "$ROOT/.build/liboqs-python"
cmake -S "$ROOT/.build/liboqs" -B "$ROOT/.build/liboqs-build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  '-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;KEM_hqc_1;KEM_hqc_3;KEM_hqc_5;SIG_ml_dsa_65' \
  -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX="$ROOT/.local"
cmake --build "$ROOT/.build/liboqs-build" --parallel "${BUILD_JOBS:-4}"
cmake --install "$ROOT/.build/liboqs-build"
python -m pip install "$ROOT/.build/liboqs-python"
cd "$ROOT"
python - <<'PY'
from crypto.primitives import KEMS, kem_keypair, encapsulate, decapsulate, signature_keypair, sign, verify, versions
from policy.engine import installed_algorithms
capabilities = installed_algorithms()
assert set(capabilities) == set(KEMS)
for a in capabilities.values():
    public, secret = kem_keypair(a['name'])
    ciphertext, shared = encapsulate(a['name'], public)
    assert decapsulate(a['name'], secret, ciphertext) == shared
public, secret = signature_keypair()
assert verify(public, b'setup check', sign(secret, b'setup check'))
print(versions())
print('Verified real operations for all configured KEMs and ML-DSA-65.')
PY
