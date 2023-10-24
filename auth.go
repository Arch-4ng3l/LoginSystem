package loginsystem

import (
	"log"
	"net/smtp"
)

// In Work

type EmailClient struct {
	email string
	auth  smtp.Auth
}

func NewEmailClient(email, password string) *EmailClient {
	auth := smtp.PlainAuth("", email, password, "smtp.gmail.com")
	ec := &EmailClient{}
	ec.auth = auth
	ec.email = email
	return ec
}
func (ec *EmailClient) SendEmail(recv []string, msg string) {
	err := smtp.SendMail("smtp.gmail.com:587", ec.auth, ec.email, recv, []byte(msg))
	if err != nil {
		log.Println(err)
	}
}
