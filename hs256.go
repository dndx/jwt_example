package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/newtoken", func(w http.ResponseWriter, r *http.Request) {
		token := jwt.New(jwt.SigningMethodHS256)
		token.Claims["access"] = "1" // this only supports string, unfortunately
		tokenString, err := token.SignedString([]byte("secret"))
		if err != nil {
			log.Println(err)
			log.Panic("Sign() failed")
		}
		fmt.Fprintf(w, tokenString)
	})

	http.HandleFunc("/secret_data", func(w http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})

		if err == nil && token.Valid {
			fmt.Fprintf(w, "secret data")
		} else {
			http.Error(w, "Authentication token is missing or incorrect", 401)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
