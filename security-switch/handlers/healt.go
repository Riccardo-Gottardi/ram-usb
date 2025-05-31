package handlers

/*
Health check handler for the Security-Switch.
Provides status verification for the mTLS gateway service
and optionally checks connectivity to Database-Vault.
*/

import (
	"encoding/json"
	"net/http"
	"security_switch/config"
	"security_switch/interfaces"
	"security_switch/types"
)

// HealthHandler verifies Security-Switch status
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Basic health check response
	response := types.HealthResponse{
		Success: true,
		Message: "Security-Switch operational",
		Service: "security-switch",
		Status:  "healthy",
	}

	// Optional: check Database-Vault connectivity
	if r.URL.Query().Get("check_deps") == "true" {
		cfg := config.GetConfig()
		dbClient, err := interfaces.NewDatabaseVaultClient(
			cfg.DatabaseVaultIP,
			cfg.ClientCertFile,
			cfg.ClientKeyFile,
			cfg.CACertFile,
		)

		if err != nil {
			response.Dependencies = map[string]string{
				"database-vault": "connection error",
			}
		} else {
			// Try to check Database-Vault health
			if dbClient.CheckHealth() {
				response.Dependencies = map[string]string{
					"database-vault": "healthy",
				}
			} else {
				response.Dependencies = map[string]string{
					"database-vault": "unhealthy",
				}
			}
		}
	}

	json.NewEncoder(w).Encode(response)
}
