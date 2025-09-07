#!/usr/bin/env bash
docker run --rm -it -v $(pwd):/src ghcr.io/webassembly/wasi-sdk:wasi-sdk-27 sh -c "\$CC --target=wasm32-wasi -O2 -o /src/service.wasm /src/service.c"
