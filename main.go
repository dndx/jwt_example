package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	signingMethod = "ES512"
)

var (
	publicKey         []byte // the private key
	privateKey        []byte // the public key
	ecdsaPublicKey    *ecdsa.PublicKey
	ecdsaPrivateKey   *ecdsa.PrivateKey
	signingMethodInst jwt.SigningMethod
)

func main() {
	var err error
	// initialize private key
	privateKey, err = ioutil.ReadFile("secp521r1-key.pem")
	if err != nil {
		log.Panic("Could not read private key file")
	}

	publicKey, err = ioutil.ReadFile("secp521r1-key.pub")
	if err != nil {
		log.Panic("Could not read public key file")
	}

	ecdsaPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(privateKey)
	if err != nil {
		log.Panic("Unable to parse ECDSA private key: %v", err)
	}

	ecdsaPublicKey, err = jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Panic("Unable to parse ECDSA public key: %v", err)
	}

	signingMethodInst := jwt.GetSigningMethod(signingMethod)

	http.HandleFunc("/newtoken", func(w http.ResponseWriter, r *http.Request) {
		token := jwt.New(signingMethodInst)
		token.Claims["access"] = "1" // this only supports string, unfortunately
		tokenString, err := token.SignedString(ecdsaPrivateKey)
		if err != nil {
			log.Panic("Sign() failed")
		}
		fmt.Fprintf(w, tokenString)
	})

	http.HandleFunc("/secret_data", func(w http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
			return ecdsaPublicKey, nil
		})

		if err == nil && token.Valid {
			fmt.Fprintf(w, "secret data")
		} else {
			http.Error(w, "Authentication token is missing or incorrect", 401)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
