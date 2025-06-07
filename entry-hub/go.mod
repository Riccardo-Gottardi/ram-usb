// Entry-Hub module for R.A.M.-U.S.B. distributed backup system
// Implements HTTPS REST API with mTLS client for Security-Switch communication
module https_server

go 1.24.1

// Cryptographic utilities for Argon2id password hashing and secure salt generation
require golang.org/x/crypto v0.38.0

// System-level dependencies (automatically managed)
require golang.org/x/sys v0.33.0 // indirect
