package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

const (
	signingMethod = "ES512"
)

var (
	ecdsaPublicKey    [2]*ecdsa.PublicKey
	ecdsaPrivateKey   [2]*ecdsa.PrivateKey
	signingMethodInst jwt.SigningMethod
	keys              = [2]string{"secp521r1-key1", "secp521r1-key2"}
)

func main() {
	for i, k := range keys {
		// initialize private key
		privateKey, err := ioutil.ReadFile(k + ".pem")
		if err != nil {
			log.Panic("Could not read private key file")
		}

		publicKey, err := ioutil.ReadFile(k + ".pub")
		if err != nil {
			log.Panic("Could not read public key file")
		}

		ecdsaPrivateKey[i], err = jwt.ParseECPrivateKeyFromPEM(privateKey)
		if err != nil {
			log.Panic("Unable to parse ECDSA private key: %v", err)
		}

		ecdsaPublicKey[i], err = jwt.ParseECPublicKeyFromPEM(publicKey)
		if err != nil {
			log.Panic("Unable to parse ECDSA public key: %v", err)
		}
	}

	signingMethodInst := jwt.GetSigningMethod(signingMethod)

	http.HandleFunc("/newtoken", func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil {
			log.Panic("Could not parse incoming request!")
		}
		kId, err := strconv.Atoi(r.Form.Get("kid"))
		if err != nil || kId < 1 || kId > 2 {
			log.Panic("Invalid Kid")
		}

		token := jwt.New(signingMethodInst)
		token.Claims["access"] = "1" // this only supports string, unfortunately
		token.Claims["kid"] = strconv.Itoa(kId)
		tokenString, err := token.SignedString(ecdsaPrivateKey[kId-1])
		if err != nil {
			log.Panic("Sign() failed")
		}
		fmt.Fprintf(w, tokenString)
	})

	http.HandleFunc("/secret_data", func(w http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
			kId, err := strconv.Atoi(token.Claims["kid"].(string))
			if err != nil || kId < 1 || kId > 2 {
				log.Panic("Invalid Kid")
			}
			return ecdsaPublicKey[kId-1], nil
		})

		if err == nil && token.Valid {
			fmt.Fprintf(w, "secret data")
		} else {
			http.Error(w, "Authentication token is missing or incorrect", 401)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
