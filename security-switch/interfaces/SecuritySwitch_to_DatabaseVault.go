package interfaces

/*
Security-Switch -> Database-Vault
mTLS client for communicating with the Database-Vault service.
Handles secure communication with the Database-Vault service
for storing user credentials using mutual TLS.
*/

// WARNING: Some functions are not explained in detail.
// WARNING: Because they are very similar to those in the EntryHub_to_SecuritySwitch.go file,
// WARNING: where they are explained in detail
import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"security_switch/types"
	"time"
)

// DatabaseVaultClient manages communication with Database-Vault
type DatabaseVaultClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewDatabaseVaultClient creates a new mTLS client for Database-Vault communication
func NewDatabaseVaultClient(databaseVaultIP string, clientCertFile, clientKeyFile, caCertFile string) (*DatabaseVaultClient, error) {
	// Load client certificate and key for mTLS
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Load CA certificate for server verification
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}
	// DA COMMENTARE MEGLIO
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Create TLS configuration with client certificate
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		ServerName:         "database-vault", // Must match the CN of the certificate
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}

	// Create HTTP client with mTLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	return &DatabaseVaultClient{
		baseURL:    fmt.Sprintf("https://%s", databaseVaultIP),
		httpClient: client,
	}, nil
}

// StoreUserCredentials sends user registration data to Database-Vault
func (c *DatabaseVaultClient) StoreUserCredentials(req types.RegisterRequest) (*types.Response, error) {
	// Convert request to JSON
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP POST request
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/store-user", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request to Database-Vault
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Database-Vault: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var dbResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&dbResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Database-Vault response: %v", err)
	}

	return &dbResponse, nil
}

// CheckHealth verifies Database-Vault connectivity
func (c *DatabaseVaultClient) CheckHealth() bool {
	httpReq, err := http.NewRequest("GET", c.baseURL+"/api/health", nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
