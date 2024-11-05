# Script to Install and deploy the web proxy 
sudo apt install golang-go
go mod init main 
go mod tidy
go build main.go utils.go proxy.go detection.go struct.go 
sudo mv main idefix-proxy
docker pull redis
docker run -d --name redis-container -p 127.0.0.1:6379:6379 redis
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
echo "Successfully installed the web proxy"
echo "To run the proxy, execute sudo ./idefix-proxy"
