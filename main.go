package main

import (
	"fmt"
	"net/http"
	"log"
	"sync"
	"encoding/json"
	"strings"
	"strconv"
	"github.com/runner989/Chirpy/database"
)

type apiConfig struct {
	mu 	sync.Mutex
	fileserverHits int
	db *database.DB
}

type ChirpRequest struct {
	Body string `json:"body"`
}

type UserRequest struct {
	Email string `json:"email"`
}

type Response struct {
	Error 		string 	`json:"error,omitempty"`
	CleanedBody string 	`json:"cleaned_body,omitempty"`
	ID			int		`json:"id,omitempty"`
	Body		string	`json:"body,omitempty"`
	Email		string	`json:"email,omitempty"`
}

var profaneWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func main() {
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("Failed to create database: %w", err)
	}

	apiCfg := &apiConfig{db: db}

	mux := http.NewServeMux()
	server := &http.Server {
		Addr: "localhost:8080",
		Handler: mux,
	}

	appFS := http.FileServer(http.Dir("."))
	mux.Handle("/app/",http.StripPrefix("/app", appFS))

	// mux.Handle("/app/*", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", appFS)))
	
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

	// Add users api
	mux.HandleFunc("/api/users", apiCfg.handlerCreateUser)

	log.Println("Listening on 8080...")
	log.Fatal(server.ListenAndServe())
}

func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	if path == "" {
		http.Error(w, "Chirp ID not specified", http.StatusBadRequest)
		return
	}
	
	chirpID, err := strconv.Atoi(path)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}
	chirp, exists, err := cfg.db.GetChirpByID(chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}
	if !exists {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}
	respondWithJSON(w, http.StatusOK, chirp)
}

func (cfg *apiConfig) handlerChirps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		cfg.createChirp(w, r)
	case http.MethodGet:
		cfg.getChirps(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	var userRequest UserRequest
	err := json.NewDecoder(r.Body).Decode(&userRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	user, err := cfg.db.CreateUser(userRequest.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}
	response := Response{ID: user.ID, Email: user.Email}
	respondWithJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	var chirpRequest ChirpRequest
	err := json.NewDecoder(r.Body).Decode(&chirpRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if len(chirpRequest.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	cleanedBody := replaceProfaneWords(chirpRequest.Body)
	chirp, err := cfg.db.CreateChirp(cleanedBody)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
		return
	}
	response := Response{ID: chirp.ID, Body: chirp.Body}
	respondWithJSON(w, http.StatusCreated, response)	
}


func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.db.GetChirps()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirps")
		return
	}
	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	htmlResponse := fmt.Sprintf(`
		<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
		</html>`, cfg.fileserverHits)
	w.Write([]byte(htmlResponse))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.mu.Lock()
	cfg.fileserverHits = 0
	cfg.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.mu.Lock()
		cfg.fileserverHits++
		cfg.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	response := Response{Error: msg}
	respondWithJSON(w, code, response)	
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Add("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
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