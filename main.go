package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/runner989/Chirpy/database"
	"golang.org/x/crypto/bcrypt"
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

	// Add users api
	mux.HandleFunc("/api/users", apiCfg.handlerCreateUser)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)

	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevokeToken)

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

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, exists, err := cfg.db.GetUserByEmail(loginRequest.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retieve user")
		return
	}
	if !exists {
		respondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(loginRequest.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if loginRequest.ExpiresInSeconds > 0 {
		if loginRequest.ExpiresInSeconds > 24*60*60 {
			loginRequest.ExpiresInSeconds = 24 * 60 * 60
		}
		expiresAt = time.Now().Add(time.Duration(loginRequest.ExpiresInSeconds) * time.Second)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		Subject:   strconv.Itoa(user.ID),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(expiresAt.UTC()),
	})

	tokenString, err := token.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	response := Response{ID: user.ID, Email: user.Email, Token: tokenString}
	// refreshToken, err := cfg.db.CreateRefreshToken(user.ID)
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Failed to generate refresh token")
	// 	return
	// }
	// response := Response{ID: user.ID, Email: user.Email, Token: tokenString, RefreshToken: refreshToken.Token}
	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	var userRequest UserRequest
	err := json.NewDecoder(r.Body).Decode(&userRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	user, err := cfg.db.CreateUser(userRequest.Email, userRequest.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}
	response := Response{ID: user.ID, Email: user.Email}
	respondWithJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		respondWithError(w, http.StatusUnauthorized, "Invalid token format")
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.jwtSecret), nil
	})
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		respondWithError(w, http.StatusUnauthorized, "Invalid token claims")
		return
	}

	userID, err := strconv.Atoi(claims.Subject)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid user ID in token")
		return
	}

	var updateUserRequest UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateUserRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, err := cfg.db.UpdateUser(userID, updateUserRequest.Email, updateUserRequest.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}

	response := Response{ID: user.ID, Email: user.Email}
	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerRefreshToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	refreshTokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if refreshTokenString == authHeader {
		respondWithError(w, http.StatusUnauthorized, "Invalid token format")
		return
	}

	refreshToken, exists, err := cfg.db.GetRefreshToken(refreshTokenString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve refresh token")
		return
	}
	if !exists || time.Now().After(refreshToken.ExpiresAt) {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	expiresAt := time.Now().Add(time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		Subject:   strconv.Itoa(refreshToken.UserID),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(expiresAt.UTC()),
	})

	tokenString, err := token.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	response := Response{Token: tokenString}
	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerRevokeToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	refreshTokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if refreshTokenString == authHeader {
		respondWithError(w, http.StatusUnauthorized, "Invalid token format")
		return
	}
	err := cfg.db.RevokeRefreshToken(refreshTokenString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to revoke refresh token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
