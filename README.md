# MTD Proxy
This project implements a secure reverse proxy in Go, featuring MTDS mechanisms and anti DDoS protection at low cost.

## Features

- Reverse proxy with dynamic proxy selection using Redis
- SSL/TLS support for secure communication
- Automatic rotation of proxies

## Requirements

- Go 1.19+
- Redis (for dynamic proxy management)
- OpenSSL (for generating self-signed certificates)
- Docker Engine

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Jxlio/MTD-PROXY-WEB/MTD-PROXY-WEB.git
cd MTD-PROXY-WEB
```
### 2. Installation 
run these commands :
```bash
sudo chmod +x install.sh
sudo ./install.sh
```

By default, the proxy listens on https://localhost. If you want to change the port or other settings, you can modify the configuration in main.go.

### 8. Test the Proxy
Once the proxy is running, you can send HTTPS requests to https://localhost or https://localhost:<port> if you changed the default port.

Use curl to test the proxy functionality:

```bash
curl -v https://localhost --insecure
```
The --insecure flag is needed because we are using a self-signed certificate. For production environments, you should use a valid certificate issued by a trusted Certificate Authority (CA).
