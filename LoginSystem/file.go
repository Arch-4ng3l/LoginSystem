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

func (accmap *AccMap) Print() {
	for _, p := range accmap.accounts {
		p.Print()
	}
}

type FileStorage struct {
	accFile  *os.File
	accPath  string
	accounts AccMap
}

func (f *FileStorage) NewFile() {
	var err error
	if _, err := os.Stat("Files"); err != nil {
		err := os.Mkdir("Files", os.ModePerm)
		if err != nil {
			return
		}
	}

	f.accPath = "Files/acc.json"
	if _, err := os.Stat(f.accPath); err != nil {
		f.accFile, err = os.Create(f.accPath)
		if err != nil {
			return
		}
	}

	raw, err := os.ReadFile(f.accPath)
	if err != nil {
		return
	}

	f.accounts.accounts = make(map[string]*Account)
	if err := json.Unmarshal(raw, &f.accounts.accounts); err != nil {
		return
	}
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

func (f *FileStorage) GetUserInformations(req *LoginRequest) *Account {
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
