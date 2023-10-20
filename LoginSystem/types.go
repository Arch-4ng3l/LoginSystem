package loginsystem

import "fmt"

type Account struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (acc *Account) Print() {
	fmt.Println("Name: " + acc.Name)
	fmt.Println("Email: " + acc.Email)
	fmt.Println("Password: " + acc.Password)
}

type LoginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (lr *LoginRequest) IsEmpty() bool {
	return lr.Name == "" || lr.Password == ""
}

func (lr *LoginRequest) Print() {
	fmt.Println("Name: " + lr.Name)
	fmt.Println("Password: " + lr.Password)
}

type SignUpRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (sr *SignUpRequest) IsEmpty() bool {
	return sr.Name == "" || sr.Email == "" || sr.Password == ""
}

func (sr *SignUpRequest) Print() {
	fmt.Println("Name: " + sr.Name)
	fmt.Println("Email: " + sr.Email)
	fmt.Println("Password: " + sr.Password)
}
