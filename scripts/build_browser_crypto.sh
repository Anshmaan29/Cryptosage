#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root=$PWD
sdk="$root/.build/hosted-deps/emsdk"
if [ ! -d "$sdk/.git" ]; then
  git clone --depth 1 --branch 4.0.23 https://github.com/emscripten-core/emsdk.git "$sdk"
fi
[ "$(git -C "$sdk" rev-parse HEAD)" = c0bb220cb6e6f4e0fabb6f6db9efd53390ef5e56 ]
if [ ! -x "$sdk/upstream/emscripten/emcc" ]; then
  "$sdk/emsdk" install 4.0.23
fi
"$sdk/emsdk" activate 4.0.23
# shellcheck disable=SC1091
source "$sdk/emsdk_env.sh"
export PATH="$root/.venv/bin:$PATH"
[ "$(git -C .build/liboqs rev-parse HEAD)" = 5a1a854b0dc9f2141bdc771c555ee60c37950183 ]
[ -z "$(git -C .build/liboqs status --porcelain --untracked-files=no)" ]
build="$root/.build/browser-oqs"
output="$root/.build/browser-site"
mkdir -p "$output"
emcmake cmake -S .build/liboqs -B "$build" -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=OFF -DOQS_DIST_BUILD=OFF \
  -DOQS_USE_OPENSSL=OFF -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
  '-DOQS_MINIMAL_BUILD=KEM_ml_kem_768;KEM_hqc_3;SIG_ml_dsa_65'
cmake --build "$build" --parallel 4
emcc "$build/lib/liboqs.a" --no-entry -O3 -sMODULARIZE=1 -sEXPORT_ES6=1 \
  -sENVIRONMENT=web,node -sSTACK_SIZE=8388608 -sFILESYSTEM=0 \
  '-sEXPORTED_RUNTIME_METHODS=["HEAPU8","HEAPU32"]' \
  '-sEXPORTED_FUNCTIONS=["_malloc","_free","_OQS_KEM_new","_OQS_KEM_free","_OQS_KEM_keypair","_OQS_KEM_encaps","_OQS_KEM_decaps","_OQS_SIG_new","_OQS_SIG_free","_OQS_SIG_keypair","_OQS_SIG_sign","_OQS_SIG_verify"]' \
  -o "$output/liboqs.mjs"
