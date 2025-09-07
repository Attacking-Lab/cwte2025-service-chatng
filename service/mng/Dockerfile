FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat curl ca-certificates xz-utils && \
    curl https://wasmtime.dev/install.sh -sSf | bash && \
    mv ~/.wasmtime/bin/wasmtime /bin/wasmtime && \
    rm -rf ~/.wasmtime/ && \
    apt-get purge -y --auto-remove curl ca-certificates xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY service.wasm /app/service.wasm

RUN 

EXPOSE 9000
CMD socat TCP-LISTEN:9000,reuseaddr,fork EXEC:"wasmtime run --env BOTS_DIR=$BOTS_DIR --dir $BOTS_DIR /app/service.wasm"
