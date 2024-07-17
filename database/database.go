package database

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
)

type Chirp struct {
	ID int `json:"id"`
	Body string `json:"body"`
}

type User struct {
	ID int `json:"id"`
	Email string `json:"email"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type DB struct {
	path string
	mux *sync.RWMutex
}

// create new database connection and create the file if it doen't exit
func NewDB(path string) (*DB, error) {
	db := &DB {
		path: path,
		mux: &sync.RWMutex{},
	}
	err := db.ensureDB()
	return db, err
}

// create the database file if it does not exist
func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if os.IsNotExist(err) {
		initialData := DBStructure{
			Chirps: make(map[int]Chirp),
			Users: 	make(map[int]User),
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
func (db *DB) CreateChirp(body string) (Chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{ID: id, Body: body}
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

func (db *DB) CreateUser(email string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	id := len(dbStructure.Users) + 1
	user := User{ID: id, Email: email}
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