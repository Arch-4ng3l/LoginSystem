package loginsystem

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	jwt "github.com/golang-jwt/jwt/v5"
)

var jwtSecret = ""

type Storage interface {
	CreateNewUser(req *SignUpRequest) bool
	GetUserInformations(req *LoginRequest) *Account
}

type LoginSystem struct {
	listeningAddr string
	store         Storage
	urlPath       string
}

type LoginError struct {
	msg string
}

func (err LoginError) Error() string {
	return "Login Error: " + err.msg
}

type SignUpError struct {
	msg string
}

func (err SignUpError) Error() string {
	return "SignUp Error: " + err.msg
}

func NewLoginSystem(addr, path string, store Storage) *LoginSystem {
	return &LoginSystem{
		listeningAddr: addr,
		urlPath:       path,
		store:         store,
	}
}

func (ls *LoginSystem) Run(secret string) error {
	fmt.Println("Starting Login System")
	jwtSecret = secret
	http.HandleFunc(ls.urlPath+"/login", httpFuncToHandler(ls.handleLogin))
	http.HandleFunc(ls.urlPath+"/signup", httpFuncToHandler(ls.handleSignUp))
	return nil
}

func (ls *LoginSystem) handleLogin(w http.ResponseWriter, r *http.Request) error {
	loginReq := &LoginRequest{}
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(loginReq)

	if loginReq.IsEmpty() {
		return fmt.Errorf("Not A Valid Request Format")
	}

	acc := ls.store.GetUserInformations(loginReq)
	if acc == nil {
		return LoginError{
			msg: "User Does Not Exist",
		}
	}

	if createHash(loginReq.Password) != acc.Password {
		return LoginError{
			msg: "Invalid Account Password",
		}
	}

	token, err := createJWT(acc)
	if err != nil {
		return err
	}

	return json.NewEncoder(w).
		Encode(map[string]string{
			"token": token,
		})
}

func (ls *LoginSystem) handleSignUp(w http.ResponseWriter, r *http.Request) error {
	signupReq := &SignUpRequest{}
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(signupReq)

	if signupReq.IsEmpty() {
		return SignUpError{
			msg: "Not A Valid Request Format",
		}
	}

	regex, _ := regexp.Compile("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")

	if !regex.Match([]byte(signupReq.Email)) {
		return SignUpError{
			msg: "Not A Valid Email",
		}
	}
	signupReq.Password = createHash(signupReq.Password)

	if !ls.store.CreateNewUser(signupReq) {
		return SignUpError{
			msg: "Couldnt Create New User",
		}
	}

	acc := &Account{
		Name:     signupReq.Name,
		Email:    signupReq.Email,
		Password: signupReq.Password,
	}

	token, err := createJWT(acc)

	if err != nil {
		return err
	}

	return json.NewEncoder(w).
		Encode(map[string]string{
			"token": token,
		})

}

func (ls *LoginSystem) AuthWithJWT(r *http.Request) bool {
	cookie, err := r.Cookie("token")
	temp := ""
	if err != nil {
		temp = r.Header.Get("token")
	} else {
		temp = cookie.Value
	}

	token, err := parseJWT(temp)
	if err != nil {
		return false
	}

	name, ok := token.Claims.(jwt.MapClaims)["username"].(string)
	password, ok2 := token.Claims.(jwt.MapClaims)["password"].(string)
	if !ok && !ok2 {
		return false
	}

	loginReq := &LoginRequest{
		Name:     name,
		Password: password,
	}
	acc := ls.store.GetUserInformations(loginReq)

	if password != acc.Password {
		return false
	}

	return true
}

type httpFunction func(http.ResponseWriter, *http.Request) error

func httpFuncToHandler(f httpFunction) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			log.Println(err)
		}
	}
}

func createHash(in string) string {
	hash := sha256.New()
	_, err := hash.Write([]byte(in))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func createJWT(acc *Account) (string, error) {
	claims := jwt.MapClaims{
		"expires":  100000,
		"username": acc.Name,
		"password": acc.Password,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(jwtSecret))
}

func parseJWT(jwtToken string) (*jwt.Token, error) {
	return jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing Method")
		}
		return []byte(jwtSecret), nil
	})
}
