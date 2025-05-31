package main

import (
	"bytes"
	"crypto/tls" // Import the tls package
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Define a struct that matches the structure of your JSON data
type Data struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	// Replace this with the URL of your HTTPS server that uses a self-signed certificate
	// For demonstration, I'll use a local HTTPS server that I might run with a self-signed cert.
	// You would replace this with your actual test server URL.

	err := godotenv.Load("../priv/.env") // Load environment variables from .env file
	if err != nil {
		log.Fatal("Error loading .env file")
		return
	}

	serverInterfaceIp := os.Getenv("SERVER_INTERFACE_IP")
	email := "pippo.balordo@gmail.com"
	password := "password123"

	registerUser(email, password, serverInterfaceIp)
}

func registerUser(email string, password string, interfaceIp string) {
	url := "https://localhost:8443/api/register" // Example self-signed server URL

	data := Data{
		Email:    email,
		Password: password,
	}

	requestBody, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	fmt.Println("Generated JSON Body:", string(requestBody))

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Error creating POST request: %v", err)
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// --- THIS IS THE KEY PART FOR IGNORING SELF-SIGNED CERTS ---
	// Create a custom Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // WARNING: ONLY FOR TESTING! DO NOT USE IN PRODUCTION!
		},
	}

	// Create an HTTP client with the custom Transport
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
	// --- END OF KEY PART ---

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making POST request: %v", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	// Adjust this based on what your test server returns for a successful POST
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { // Check for any non-2xx status
		log.Fatalf("Received unexpected HTTP status for POST: %d %s", resp.StatusCode, resp.Status)
	}

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	fmt.Println("Response Body (POST):")
	fmt.Println(string(responseBody))
}
