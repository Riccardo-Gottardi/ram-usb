package config

/*
Configuration settings for the Security-Switch mTLS server.
Contains server settings, Database-Vault connection parameters,
and certificate paths for mutual TLS authentication.
*/

// Config holds the Security-Switch configuration
type Config struct {
	// Server configuration
	ServerPort     string
	ServerCertFile string
	ServerKeyFile  string
	CACertFile     string

	// Database-Vault connection settings
	DatabaseVaultIP string
	ClientCertFile  string
	ClientKeyFile   string
}

// GetConfig returns the application configuration
// TODO: In production, load this from environment variables or config file
func GetConfig() *Config {
	return &Config{
		// Security-Switch server settings
		ServerPort:     "8444",
		ServerCertFile: "../certificates/security-switch/server.crt",
		ServerKeyFile:  "../certificates/security-switch/server.key",
		CACertFile:     "../certificates/certification-authority/ca.crt",

		// Database-Vault client settings for outgoing mTLS connections
		DatabaseVaultIP: "100.93.246.70:8445", // Replace with actual Database-Vault Tailscale IP
		ClientCertFile:  "../certificates/security-switch/client.crt",
		ClientKeyFile:   "../certificates/security-switch/client.key",
	}
}
