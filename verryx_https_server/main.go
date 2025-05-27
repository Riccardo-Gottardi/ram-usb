package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"golang.org/x/crypto/argon2"
)

// Registration request structure
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Structure to represent a user
type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
}

// Response structure
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

const usersFile = "users.json"

// Function to validate the email using a regular expression.
func isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}

// Function to generate a random salt.
// NOTE: _ is used to ignore the first parameter returned by the rand.Read function
func generateSalt() (string, error) {
	salt := make([]byte, 16)	// Create a 16byte empty slice 
	_, err := rand.Read(salt)	// fills the passed slice with cryptographically secure random bytes.
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", salt), nil	//Converts the 16 random bytes to a hexadecimal string to represent binary data in a readable way
}

// Function to hash password with Argon2
func hashPassword(password, salt string) string {
	saltBytes := []byte(salt)	// Converts the salt to a byte array because argon2.IDKey requires it
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 32*1024, 4, 32)	//hash password with Argon2id using 1 iteration, 32bytes of RAM, 4 CPU threads. Produces a 32byte hash.
	return fmt.Sprintf("%x", hash)	// Converts the hash byte array into a readable hexadecimal string
}

// Function to load users from JSON file. This function will be deleted introducing PostgreSQL
func loadUsers() ([]User, error) {
	var users []User

	// If the file does not exist, create an empty one with a JSON slice "[]"
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		err := os.WriteFile(usersFile, []byte("[]"), 0644)
		if err != nil {
			return nil, err
		}
		return users, nil
	}

	file, err := os.Open(usersFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&users)
	return users, err
}

// Function to save users in JSON file. This function will be replaced introducing PostgreSQL
func saveUsers(users []User) error {
	file, err := os.Create(usersFile)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(users)
}

// Function to check if a user already exists. This function will be replaced introducing PostgreSQL
func userExists(users []User, email string) bool {
	for _, user := range users {
		if user.Email == email {
			return true
		}
	}
	return false
}

// User registration handler
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Set Content-Type to JSON
	w.Header().Set("Content-Type", "application/json")	// Tells the client that the response will be a json
	
	// Accepts POST requests only. 
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)	// Return Error 405. MethodNotAllowed
		json.NewEncoder(w).Encode(Response{	// Create a json response to send to the server
			Success: false,
			Message: "Metodo non consentito. Usa POST.",
		})
		return
	}
	
	// Read the body of the request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Errore nella lettura della richiesta.",
		})
		return
	}
	
	// Parsing JSON
	var req RegisterRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "JSON non valido.",
		})
		return
	}
	
	// Input Validation
	if req.Email == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Email e password sono obbligatori.",
		})
		return
	}
	
	if !isValidEmail(req.Email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Formato email non valido.",
		})
		return
	}
	
	if len(req.Password) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "La password deve essere di almeno 6 caratteri.",
		})
		return
	}
	
	// Load existing users
	users, err := loadUsers()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Errore nel caricamento degli utenti.",
		})
		return
	}
	
	// Check if the user already exists
	if userExists(users, req.Email) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Utente già registrato con questa email.",
		})
		return
	}
	
	// Generate password salt and hash
	salt, err := generateSalt()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Errore nella generazione del salt.",
		})
		return
	}
	
	passwordHash := hashPassword(req.Password, salt)
	
	// Create new user
	newUser := User{
		Email:        req.Email,
		PasswordHash: passwordHash,
		Salt:         salt,
	}
	
	// Add the user to the list and save
	users = append(users, newUser)
	err = saveUsers(users)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Errore nel salvataggio dell'utente.",
		})
		return
	}
	
	// Successful response
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Utente registrato con successo!",
	})
	
	log.Printf("Nuovo utente registrato: %s", req.Email)
}

// Handler to verify that the server is working
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Server HTTPS funzionante!",
	})
}

func main() {
	// Configure the routes
	http.HandleFunc("/api/register", registerHandler)
	http.HandleFunc("/api/health", healthHandler)
	
	fmt.Println("Server HTTPS avviato su https://localhost:8443")
	fmt.Println("Endpoint disponibili:")
	fmt.Println("- POST /api/register (registrazione utenti)")
	fmt.Println("- GET  /api/health (verifica stato server)")
	fmt.Println("usa questo comando per registrare un utente:")
	fmt.Println("curl -k -X POST https://localhost:8443/api/register -d '{\"email\":\"tuo.email@example.com\",\"password\":\"password123\"}' -H \"Content-Type: application/json\"")
	
	fmt.Println("\n Per fermare il server premi Ctrl+C")
	
	// Start HTTPS server
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil))
}