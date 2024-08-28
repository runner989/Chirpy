package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/joho/godotenv"
	"github.com/runner989/Chirpy/database"
)

type apiConfig struct {
	mu             sync.Mutex
	fileserverHits int
	db             *database.DB
	jwtSecret      string
}

type ChirpRequest struct {
	Body string `json:"body"`
}

type UserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

type UpdateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Response struct {
	Error        string `json:"error,omitempty"`
	CleanedBody  string `json:"cleaned_body,omitempty"`
	ID           int    `json:"id,omitempty"`
	Body         string `json:"body,omitempty"`
	Email        string `json:"email,omitempty"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AuthorID     int    `json:"author_id,omitempty"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

var profaneWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func main() {
	godotenv.Load()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("JWT_SECRET environment variable is required")
	}

	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}

	apiCfg := &apiConfig{db: db, jwtSecret: jwtSecret}

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	appFS := http.FileServer(http.Dir("."))
	mux.Handle("/app/", http.StripPrefix("/app", appFS))

	// Add root redirect to /app
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
	})

	// Add readiness endpoint
	mux.HandleFunc("GET /api/healthz", handlerReadiness)

	// Add metrics endpoint
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)

	// Add reset endpoint
	mux.HandleFunc("/api/reset", apiCfg.handlerReset)

	// Add chirps endpoints
	mux.HandleFunc("/api/chirps", apiCfg.handlerChirps)
	mux.HandleFunc("GET /api/chirps/", apiCfg.handlerGetChirpByID)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirp)

	// Add users api
	mux.HandleFunc("/api/users", apiCfg.handlerCreateUser)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)

	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevokeToken)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerPolkaWebhooks)

	log.Println("Listening on 8080...")
	log.Fatal(server.ListenAndServe())
}

func replaceProfaneWords(body string) string {
	words := strings.Split(body, " ")
	for i, word := range words {
		for _, profane := range profaneWords {
			if strings.EqualFold(word, profane) {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
}
