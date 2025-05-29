/*
User data storage operations for the backup service.
Handles reading, writing, and querying user data from JSON files.
This is a temporary implementation that will be replaced with PostgreSQL
database operations for production use.
*/

package storage

import (
	"encoding/json"
	"https_server/types"
	"os"
)

// Function to load users from JSON file. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
func LoadUsers(usersFile string) ([]types.User, error) {
	var users []types.User

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

// Function to save users in JSON file. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
func SaveUsers(users []types.User, usersFile string) error {
	file, err := os.Create(usersFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(users)
}

// Function to check if a user already exists. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
func UserExists(users []types.User, email string) bool {
	for _, user := range users {
		if user.Email == email {
			return true
		}
	}
	return false
}
