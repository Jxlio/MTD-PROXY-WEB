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

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Jxlio/MTD-PROXY-WEB/MTD-PROXY-WEB.git
cd MTD-PROXY-WEB
```
### 2. Generate Self-Signed Certificates
To run the proxy over HTTPS, you need a self-signed SSL certificate and key. You can generate them using OpenSSL:


# Generate a self-signed certificate
```bash
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365
```

### 3. Initialize the Go Project
Make sure Go is installed and your environment is set up correctly.

```bash
go mod init 
go mod tidy
```
This will initialize the Go modules required for dependency management.

### 4. Install Redis

You must install and launch a redis instance. To do so : 
```bash
docker pull redis
docker run redis
```

### 5. Launch the Proxy
To run the reverse proxy, execute the following command from the root of the project:

```bash
go run main.go proxy.go
```
By default, the proxy listens on https://localhost. If you want to change the port or other settings, you can modify the configuration in proxy.go.

### 8. Test the Proxy
Once the proxy is running, you can send HTTPS requests to https://localhost or https://localhost:<port> if you changed the default port.

Use curl to test the proxy functionality:

```bash
curl -v https://localhost --insecure
```
The --insecure flag is needed because we are using a self-signed certificate. For production environments, you should use a valid certificate issued by a trusted Certificate Authority (CA).
