package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func (cfg *apiConfig) handlerPolkaWebhooks(w http.ResponseWriter, r *http.Request) {
	var webhookRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
	}
	err := json.NewDecoder(r.Body).Decode(&webhookRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if webhookRequest.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	_, err = cfg.db.UpdateUserChirpyRedStatus(webhookRequest.Data.UserID, true)
	if err != nil {
		if err.Error() == "user not found" {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			respondWithError(w, http.StatusInternalServerError, "Failed to update user status")
		}
		return
	}

	// Log for debugging
	log.Printf("User %d upgraded to Chirpy Red.", webhookRequest.Data.UserID)

	w.WriteHeader(http.StatusNoContent)
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

	var chirpRequest ChirpRequest
	err = json.NewDecoder(r.Body).Decode(&chirpRequest)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if len(chirpRequest.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	cleanedBody := replaceProfaneWords(chirpRequest.Body)
	chirp, err := cfg.db.CreateChirp(cleanedBody, userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
		return
	}
	response := Response{ID: chirp.ID, Body: chirp.Body, AuthorID: chirp.AuthorID}
	respondWithJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	if path == "" {
		http.Error(w, "Chirp ID not specified", http.StatusBadRequest)
		return
	}

	chirpID, err := strconv.Atoi(path)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
	}
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
	chirp, exists, err := cfg.db.GetChirpByID(chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirp")
		return
	}
	if !exists {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}
	if chirp.AuthorID != userID {
		respondWithError(w, http.StatusForbidden, "You are not allowed to delete this chirp")
		return
	}
	err = cfg.db.DeleteChirp(chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, _ *http.Request) {
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

// func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		cfg.mu.Lock()
// 		cfg.fileserverHits++
// 		cfg.mu.Unlock()
// 		next.ServeHTTP(w, r)
// 	})
// }

func respondWithError(w http.ResponseWriter, code int, msg string) {
	response := Response{Error: msg}
	respondWithJSON(w, code, response)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Add("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
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

	refreshToken, err := cfg.db.CreateRefreshToken(user.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate refresh token")
		return
	}
	//response := Response{ID: user.ID, Email: user.Email, Token: tokenString, RefreshToken: refreshToken.Token}
	response := Response{
		ID:           user.ID,
		Email:        user.Email,
		Token:        tokenString,
		RefreshToken: refreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed,
	}

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
	response := Response{
		ID:          user.ID,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed}
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
