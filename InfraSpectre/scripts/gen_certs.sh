#!/bin/zsh
# Generate self-signed CA, server, and client certs for mTLS
set -e
CERTS_DIR="certs"
mkdir -p $CERTS_DIR
cd $CERTS_DIR

# 1. CA key and cert
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=InfraSpectre-CA"

# 2. Server key and CSR
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -sha256

# 3. Client key and CSR
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=flowagent"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650 -sha256

# Clean up CSRs
rm server.csr client.csr

cd ..
echo "Certs generated in $CERTS_DIR: ca.crt, server.crt, client.crt, and keys."
