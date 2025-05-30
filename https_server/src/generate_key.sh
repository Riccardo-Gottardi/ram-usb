#!/bin/bash

# Script to generate all necessary certificates for HTTPS server and mTLS

# I leave here the meaning of the various openssl flags for convenience
#
# -in               : Input file
# -out              : Output file (where to save keys, certificates, etc.)
# -new              : Create a new certificate request
# -x509             : Generate an X.509 certificate
# -days             : Validity period of the certificate
# -key              : Private key file to use for signing or generation
# -subj             : Specifies the Distinguished Name (DN) of the certificate inline, without interactive prompt
# -req              : Indicates that you are working on a certificate request (CSR)
# -CA               : Certificate Authority (CA) file used for signing
# -CAkey            : Private key file of the CA used for signing
# -CAcreateserial   : Creates a new serial file for the CA if it does not exist (needed for signing multiple certificates)
# -extfile          : Specifies the path to the configuration file from which to read the section indicated by -extensions.
# -extensions       : Name of the extensions section to apply to the certificate.
    #[V3_req] is the section that contains extensions:
    # Keyusage: for what the key can be used (data encryption).
    # Extendedkeyusage: more specific uses (Serverauth for https).
    # Subjectname: List of alternative hosts valid for the certificate (Localhost, 127.0.0.1, ...).

set -e  # Exit if any command fails

echo "Generating SSL/TLS certificates for HTTPS Server and mTLS"

# Create the 'priv' directory if it doesn't exist
mkdir -p ../priv
cd ../priv

echo "Working directory: $(pwd)"

#This command generates a 4096-bit RSA private key, named ca.key, which will be used by the CA to sign digital certificates.
openssl genrsa \
  -out ca.key 4096

# Generate the self-signed CA certificate
# It is used to verify that the certificate is signed by the CA. It must be distributed to client/server.
# The server will use ca.crt to verify the client certificate.
# The client will use ca.crt to verify the server certificate.
openssl req \
  -new \
  -x509 \
  -days 365 \
  -key ca.key \
  -out ca.crt \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=DevCA/CN=Development CA"

# Generate the server's private key
# It should be used by the server to decipher the data and to demonstrate their identity.
openssl genrsa \
  -out server.key 4096

# Generate the server's Certificate Signing Request (CSR)
# It is used by the server to obtain a certificate signed by the CA
# It is eliminated after obtaining the certificate
openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=HTTPSServer/CN=localhost"

# Create a configuration file for the server certificate with SAN (Subject Alternative Names)
# Temporary file used to add extensions to the server certificate
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
# The Certificate X.509 of the server, signed by the CA. It is used by the client to check the identity of the server.
openssl x509 \
  -req \
  -in server.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Generate the client's private key (for mTLS)
# It is used to demonstrate the identity of the cilent to the server in mTLS
openssl genrsa \
  -out client.key 4096

# Generate the client's Certificate Signing Request (CSR)
# It is used by the server to obtain a certificate signed by the CA
# It is deleted after obtaining the certificate
openssl req \
  -new \
  -key client.key \
  -out client.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=HTTPSClient/CN=backup-client"

# Generate the client certificate signed by the CA
# The client certificate, signed by the CA. It is used by the server to check the identity of the client.
openssl x509 \
  -req \
  -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365

# Clean up temporary files
rm -f server.csr client.csr server.conf

# Set correct permissions
chmod 600 *.key
chmod 644 *.crt

echo "CERTIFICATES SUCCESSFULLY GENERATED!"
echo "------------------------------------"
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