package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	// Database
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// AWS Cognito
	CognitoRegion      string
	CognitoUserPoolID  string
	CognitoAppClientID string

	// Server
	ServerPort string
	Env        string
}

func Load() *Config {
	// Load .env file if exists
	godotenv.Load()

	return &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "admin"),
		DBPassword: getEnv("DB_PASSWORD", "password"),
		DBName:     getEnv("DB_NAME", "location_system"),

		CognitoRegion:      getEnv("AWS_COGNITO_REGION", "us-east-1"),
		CognitoUserPoolID:  getEnv("AWS_COGNITO_USER_POOL_ID", ""),
		CognitoAppClientID: getEnv("AWS_COGNITO_APP_CLIENT_ID", ""),

		ServerPort: getEnv("SERVER_PORT", "8080"),
		Env:        getEnv("ENV", "development"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		log.Printf("Invalid integer value for %s, using default", key)
	}
	return defaultValue
}
