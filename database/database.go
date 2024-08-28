package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Chirp struct {
	ID       int    `json:"id"`
	Body     string `json:"body"`
	AuthorID int    `json:"author_id"`
}

type User struct {
	ID             int    `json:"id"`
	Email          string `json:"email"`
	HashedPassword string `json:"password"`
	IsChirpyRed    bool   `json:"is_chirpy_red"`
}

type DBStructure struct {
	Chirps        map[int]Chirp           `json:"chirps"`
	Users         map[int]User            `json:"users"`
	RefreshTokens map[string]RefreshToken `json:"refresh_token"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// create new database connection and create the file if it doen't exit
func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	err := db.ensureDB()
	return db, err
}

// create the database file if it does not exist
func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if os.IsNotExist(err) {
		initialData := DBStructure{
			Chirps:        make(map[int]Chirp),
			Users:         make(map[int]User),
			RefreshTokens: make(map[string]RefreshToken),
		}
		return db.writeDB(initialData)
	}
	return err
}

// read the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	data, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}
	var dbStructure DBStructure
	err = json.Unmarshal(data, &dbStructure)
	return dbStructure, err
}

// write the database to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	data, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0644)
}

// Create a new chirp and save it to disk
func (db *DB) CreateChirp(body string, authorID int) (Chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{ID: id, Body: body, AuthorID: authorID}
	dbStructure.Chirps[id] = chirp
	err = db.writeDB(dbStructure)
	return chirp, err
}

// return all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].ID < chirps[j].ID
	})

	return chirps, nil
}

// get chirp by ID
func (db *DB) GetChirpByID(chirpID int) (Chirp, bool, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, false, err
	}
	chirp, exists := dbStructure.Chirps[chirpID]
	return chirp, exists, nil
}

func (db *DB) DeleteChirp(id int) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	if _, exists := dbStructure.Chirps[id]; !exists {
		return errors.New("chirp not found")
	}
	delete(dbStructure.Chirps, id)
	return db.writeDB(dbStructure)
}

func (db *DB) CreateUser(email, password string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return User{}, errors.New("email already exists")
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	id := len(dbStructure.Users) + 1
	user := User{ID: id, Email: email, HashedPassword: string(hashedPassword), IsChirpyRed: false}
	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	return user, err
}

func (db *DB) GetUsers() ([]User, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	users := make([]User, 0, len(dbStructure.Users))
	for _, user := range dbStructure.Users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})
	return users, nil
}

func (db *DB) GetUserByEmail(email string) (User, bool, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, false, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, true, nil
		}
	}

	return User{}, false, nil
}

func (db *DB) UpdateUser(id int, email, password string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, exists := dbStructure.Users[id]
	if !exists {
		return User{}, errors.New("user not found")
	}
	user.Email = email
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	user.HashedPassword = string(hashedPassword)
	dbStructure.Users[id] = user
	err = db.writeDB(dbStructure)
	return user, err
}

func (db *DB) UpdateUserChirpyRedStatus(userID int, isChirpyRed bool) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	user, exists := dbStructure.Users[userID]
	if !exists {
		return User{}, errors.New("user not found")
	}
	user.IsChirpyRed = isChirpyRed
	dbStructure.Users[userID] = user
	err = db.writeDB(dbStructure)
	return user, err
}

func (db *DB) CreateRefreshToken(userID int) (RefreshToken, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return RefreshToken{}, err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return RefreshToken{}, err
	}

	token := hex.EncodeToString(tokenBytes)
	refreshToken := RefreshToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	}

	dbStructure.RefreshTokens[token] = refreshToken
	err = db.writeDB(dbStructure)
	return refreshToken, err
}

func (db *DB) GetRefreshToken(token string) (RefreshToken, bool, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return RefreshToken{}, false, err
	}

	refreshToken, exists := dbStructure.RefreshTokens[token]
	return refreshToken, exists, nil
}

func (db *DB) RevokeRefreshToken(token string) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	delete(dbStructure.RefreshTokens, token)
	return db.writeDB(dbStructure)
}
