package loginsystem

import (
	"encoding/json"
	"os"
	"sync"
)

var startPath = "Files/"

type AccMap struct {
	sync.Mutex
	accounts map[string]*Account
}

type FileStorage struct {
	accFile  *os.File
	accPath  string
	accounts AccMap
}

func (f *FileStorage) CreateNew() {
	err := os.Mkdir("Files", os.ModePerm)
	if err != nil {
		return
	}
	f.accPath = startPath + "acc.json"
	f.accFile, err = os.Create(f.accPath)
	if err != nil {
		return
	}

	raw, err := os.ReadFile(f.accPath)
	if err != nil {
		return
	}

	var accounts map[string]*Account
	if err := json.Unmarshal(raw, &accounts); err != nil {
		return
	}

	f.accounts.accounts = accounts

}

func (f *FileStorage) CreateNewUser(req *SignUpRequest) bool {

	f.accounts.Lock()
	defer f.accounts.Unlock()

	_, ok := f.accounts.accounts[req.Name]
	if ok {
		return false
	}
	acc := &Account{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}
	f.accounts.accounts[req.Name] = acc

	if err := f.write(); err != nil {
		return false
	}

	return true
}

func (f *FileStorage) GetUserInformation(req *LoginRequest) *Account {
	f.accounts.Lock()
	defer f.accounts.Unlock()

	acc, ok := f.accounts.accounts[req.Name]
	if ok {
		return acc
	}

	return nil
}

func (f *FileStorage) write() error {
	updatedJson, err := json.Marshal(f.accounts.accounts)
	if err != nil {
		return err
	}
	return os.WriteFile(f.accPath, updatedJson, 0666)
}
