FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends \
    swtpm tpm2-tools python3 python3-cryptography openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY probe.py /probe.py
CMD ["python3", "/probe.py"]
