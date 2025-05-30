#!/bin/bash

# Script to generate all necessary certificates for HTTPS server and mTLS

set -e  # Exit if any command fails

echo "Generating SSL/TLS certificates for HTTPS Server and mTLS"
echo "=========================================================="

# Create the 'priv' directory if it doesn't exist
mkdir -p ../priv
cd ../priv

echo "Working directory: $(pwd)"

# 1. Generate the CA (Certificate Authority) private key
echo "1. Generating CA private key..."
openssl genrsa -out ca.key 4096

# 2. Generate the self-signed CA certificate
echo "2. Generating CA certificate..."
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=DevCA/CN=Development CA"

# 3. Generate the server's private key
echo "3. Generating server private key..."
openssl genrsa -out server.key 4096

# 4. Generate the server's Certificate Signing Request (CSR)
echo "4. Generating server CSR..."
openssl req -new -key server.key -out server.csr -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=HTTPSServer/CN=localhost"

# 5. Create a configuration file for the server certificate with SAN (Subject Alternative Names)
echo "5. Creating server certificate config..."
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

# 6. Generate the server certificate signed by the CA
echo "6. Generating server certificate signed by the CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server.conf

# 7. Generate the client's private key (for mTLS)
echo "7. Generating client private key..."
openssl genrsa -out client.key 4096

# 8. Generate the client's Certificate Signing Request (CSR)
echo "8. Generating client CSR..."
openssl req -new -key client.key -out client.csr -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=HTTPSClient/CN=backup-client"

# 9. Generate the client certificate signed by the CA
echo "9. Generating client certificate signed by the CA..."
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

# 10. Clean up temporary files
echo "10. Cleaning up temporary files..."
rm -f server.csr client.csr server.conf

# 11. Set correct permissions
echo "11. Setting permissions..."
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "CERTIFICATES SUCCESSFULLY GENERATED!"
echo "===================================="
echo "Files generated in: $(pwd)"
echo ""
echo "File list:"
ls -la *.crt *.key
echo ""
echo "Certificate structure:"
echo "├── ca.crt + ca.key         → Certificate Authority (CA)"
echo "├── server.crt + server.key → HTTPS Server Certificate"
echo "└── client.crt + client.key → Client Certificate for mTLS"
echo ""
echo "Your HTTPS server is now ready to go!"
echo ""
echo "To test the server certificate:"
echo "   openssl x509 -in server.crt -text -noout"
echo ""
echo "To verify HTTPS connection:"
echo "   curl -v --cacert ca.crt https://localhost:8443/api/health"
echo "   # or with --insecure to skip verification"