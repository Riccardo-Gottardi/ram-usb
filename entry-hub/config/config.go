package config

/*
Configuration settings for the Entry-Hub HTTPS service.
Contains server configuration including Security-Switch connection, parameters
and mTLS certificate paths.
*/

// Config holds the application configuration
type Config struct {
	SecuritySwitchIP string
	ClientCertFile   string
	ClientKeyFile    string
	CACertFile       string
}

// GetConfig returns the application configuration
// TODO: In production, load this from environment variables or config file
func GetConfig() *Config {
	return &Config{
		SecuritySwitchIP: "100.93.246.69:8444",                             // Replace with actual Security-Switch IP and port. This is the macbook Tailscale IP
		ClientCertFile:   "../certificates/entry-hub/client.crt",           // Path to client certificate for mTLS
		ClientKeyFile:    "../certificates/entry-hub/client.key",           // Path to client private key for mTLS
		CACertFile:       "../certificates/certification-authority/ca.crt", // Path to CA certificate
	}
}
