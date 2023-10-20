package main

import loginsystem "github.com/Arch-4ng3l/LoginSystem/LoginSystem"

func main() {
	var f *loginsystem.FileStorage = &loginsystem.FileStorage{}
	f.NewFile()

	req := &loginsystem.SignUpRequest{}
	req.Name = "Test"
	req.Email = "Test@gmai.com"
	req.Password = "test"
	f.CreateNewUser(req)

	req2 := &loginsystem.SignUpRequest{}
	req2.Name = "Test2"
	req2.Email = "Test@gmai.com"
	req2.Password = "Test2"
	if f.CreateNewUser(req2) {
		print("suc")
	}
}
