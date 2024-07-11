package main

import (
	"fmt"
	"net/http"
	"log"
	"sync"
	"encoding/json"
	"strings"
)

type apiConfig struct {
	mu 	sync.Mutex
	fileserverHits int
}

type Chirp struct {
	Body string `json:"body"`
}

type Response struct {
	Error 		string 	`json:"error,omitempty"`
	CleanedBody string 	`json:"cleaned_body,omitempty"`
}

var profaneWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}


func main() {
	mux := http.NewServeMux()
	server := &http.Server {
		Addr: "localhost:8080",
		Handler: mux,
	}

	appFS := http.FileServer(http.Dir("."))
	apiCfg := &apiConfig{}
	mux.Handle("/app/*", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", appFS)))
	
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

	// Add chirp validation endpoint
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.handlerValidateChirp)

	log.Println("Listening on 8080...")
	log.Fatal(server.ListenAndServe())
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

func (cfg *apiConfig) handlerValidateChirp(w http.ResponseWriter, r *http.Request) {
	var chirp Chirp
	err := json.NewDecoder(r.Body).Decode(&chirp)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(chirp.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := replaceProfaneWords(chirp.Body)
	response := Response{CleanedBody: cleanedBody}
	respondWithJSON(w, http.StatusOK, response)
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