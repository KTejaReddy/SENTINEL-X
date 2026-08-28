# LAB ONLY — authorized testing tooling inside the isolated cyber range.
FROM kalilinux/kali-rolling:latest

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nmap \
        curl \
        jq \
        python3 \
        python3-pip \
        dnsutils \
    && pip3 install --break-system-packages --no-cache-dir httpx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Interactive:  docker compose -f cyber-range/docker-compose.lab.yml exec attacker bash
CMD ["/entrypoint.sh"]
