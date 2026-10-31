FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap libseccomp2 strace procps docker.io git curl ca-certificates build-essential libffi-dev pkg-config zstd fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH=/root/.cargo/bin:/opt/lean/bin:/opt/argus/bin:$PATH
RUN CARGO_BUILD_JOBS=2 cargo install cedar-policy-cli --version 4.13.0 --locked
RUN mkdir -p /opt/lean && curl -fL https://github.com/leanprover/lean4/releases/download/v4.34.1/lean-4.34.1-linux_aarch64.tar.zst | tar --zstd -x -C /opt/lean --strip-components=1
RUN python -m venv /opt/argus && /opt/argus/bin/pip install uv
# Bubblewrap intentionally has no procfs/loader cache; retain the identical
# trusted Python library in the dynamic loader's default search directory.
RUN cp /usr/local/lib/libpython3.11.so.1.0 /usr/lib/aarch64-linux-gnu/libpython3.11.so.1.0
WORKDIR /workspace
