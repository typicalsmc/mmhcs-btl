FROM python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends bash openssl dnsmasq && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /lab/requirements.txt
RUN pip install --no-cache-dir -r /lab/requirements.txt
COPY lab/ /lab/
COPY scripts/revoke-cert.sh /lab/revoke-cert.sh
COPY docker/dnsmasq.conf /lab/dnsmasq.conf
