# Create a key and a self-signed certificate
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
```

<br><br><br>

# Create a public and private keys 
```bash
ssh-keygen -t rsa -b 4096 -C "tu@email.com"
```