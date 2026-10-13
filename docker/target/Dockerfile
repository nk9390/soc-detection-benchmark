FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install essential packages
RUN apt-get update && apt-get install -y \
    auditd \
    audispd-plugins \
    rsyslog \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    net-tools \
    iproute2 \
    procps \
    cron \
    sudo \
    vim \
    nmap \
    netcat-openbsd \
    openssh-client \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Configure auditd for comprehensive syscall logging
COPY auditd.rules /etc/audit/rules.d/soc-benchmark.rules

# Configure rsyslog
RUN sed -i 's/#module(load="imklog")/module(load="imklog")/' /etc/rsyslog.conf

# Clone Atomic Red Team
RUN git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Create test user for privilege escalation tests
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpass" | chpasswd

# Create startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /opt/atomic-red-team

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
