#!/bin/bash

# Script to generate all necessary certificates for HTTPS server and mTLS

set -e  # Exit if any command fails

echo "Generating SSL/TLS certificates for HTTPS Server and mTLS"

# Create the 'priv' directory if it doesn't exist
mkdir -p ../priv
cd ../priv

echo "Working directory: $(pwd)"

# Generate the CA private key
openssl genrsa -out ca.key 4096

# Generate the self-signed CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=DevCA/CN=Development CA"

# Generate the server's private key
openssl genrsa -out server.key 4096

# Generate the server's Certificate Signing Request (CSR)
openssl req -new -key server.key -out server.csr -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=HTTPSServer/CN=localhost"

# Create a configuration file for the server certificate with SAN (Subject Alternative Names)
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = HTTPSServer
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate the server certificate signed by the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server.conf

# Generate the client's private key (for mTLS)
openssl genrsa -out client.key 4096

# Generate the client's Certificate Signing Request (CSR)
openssl req -new -key client.key -out client.csr -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=HTTPSClient/CN=backup-client"

# Generate the client certificate signed by the CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

# Clean up temporary files
rm -f server.csr client.csr server.conf

# Set correct permissions
chmod 600 *.key
chmod 644 *.crt

echo "CERTIFICATES SUCCESSFULLY GENERATED!"
echo "-----------------------------------"
echo "Files generated in: $(pwd)"
echo ""
echo "File list:"
ls -la *.crt *.key
echo ""
echo "To test the server certificate:"
echo "   openssl x509 -in server.crt -text -noout"
echo ""
echo "To verify HTTPS connection:"
echo "   curl -v --cacert ca.crt https://localhost:8443/api/health"
echo "   # or with --insecure to skip verification"