# Base image
FROM golang:latest

ENV GOTOOLCHAIN=auto

# Set working directory
WORKDIR /app

# Install System Dependencies
# nmap: Network scanner
# chromium: Headless browser for Katana/Gowitness
# libpcap-dev: Required for Naabu
# git: For go install
RUN apt-get update && apt-get install -y \
    nmap \
    chromium \
    libpcap-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Pre-install ProjectDiscovery Tools (and others)
# Pin versions — update intentionally via ./xpfarm.sh update
# To upgrade a single tool: docker compose build --build-arg NUCLEI_VERSION=latest
ARG SUBFINDER_VERSION=v2.13.0
ARG NAABU_VERSION=v2.5.0
ARG HTTPX_VERSION=v1.9.0
ARG KATANA_VERSION=v1.5.0
ARG UNCOVER_VERSION=v1.2.0
ARG URLFINDER_VERSION=v0.0.3
ARG NUCLEI_VERSION=v3.7.1
ARG CVEMAP_VERSION=v1.0.0
ARG GOWITNESS_VERSION=v3.1.1
ARG WAPPALYZER_VERSION=v0.2.65

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} && \
    go install -v github.com/projectdiscovery/uncover/cmd/uncover@${UNCOVER_VERSION} && \
    go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@${URLFINDER_VERSION} && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@${CVEMAP_VERSION} && \
    go install -v github.com/sensepost/gowitness@${GOWITNESS_VERSION} && \
    go install -v github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@${WAPPALYZER_VERSION}

# Copy Go Modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy Source Code
COPY . .

# Build the Application
RUN go build -o xpfarm main.go

# Expose Port
EXPOSE 8888

# Environment Variables
# Ensure Go bin is in PATH (it usually is in golang images, but explicit is good)
ENV PATH="/go/bin:${PATH}"

# Run the application
CMD ["./xpfarm"]
