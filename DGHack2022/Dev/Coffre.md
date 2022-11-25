# Coffre-fort Secret

> Le coffre-fort secret ne semble pas déchiffrer correctement. Corrigez-le pour obtenir des points. Il y a peut-être d'autres problèmes, qui sait !

Code original qui ne fonctionne pas :

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

var bytes = []byte{53, 22, 66, 29, 75, 43, 14, 95, 34, 65, 82, 10, 23, 33, 17, 50}

const MySecret string = "\nsecret=Something_AbCdEfGhIjKlM\n"

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		panic(err)
	}
	return data
}

// This method encrypts a given text
func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	// We return the ciper text as base64
	return Encode(cipherText), nil
}

// This method decrypts a given text
func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	// We first decode the base64 input text
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(cipherText, plainText)
	return string(plainText), nil
}

func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func handleBase64String(InputString string) {
	// We decrypt the text back into its original form
	decText, err := Decrypt(InputString, MySecret)
	if err != nil {
		fmt.Println("error decrypting your encrypted text: ", err)
	}
	fmt.Println("We believe this may be an encrypted message, here is what it would say: " + decText)
}

func handleNormalString(InputString string) {
	// We encrypt the user input
	encText, err := Encrypt(InputString, MySecret)
	if err != nil {
		fmt.Println("error encrypting your classified text: ", err)
	}
	fmt.Println("The message was successfully encrypted: " + encText)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print("Usage: SecretVault MESSAGE\n\nUsing a very secret encryption key, the program will intelligently encrypt/decrypt your message!\n")
		return
	}
	InputString := strings.Join(os.Args[1:], " ")
	InputString = strings.Replace(InputString, '\n', "", -1)

	// If the input text is suspected to be an encrypted message, we decrypt it and display its content
	if IsBase64(InputString) {
		go handleBase64String(InputString)
	}
	handleNormalString(InputString)
}
```

## Description

On a un code en go qui peut encrypter et décrypter des messages.

La première chose à faire est de corriger les erreurs pour que le code se lance:
> ./vault_original.go:85:45: cannot use '\n' (untyped rune constant 10) as string value in argument to strings.Replace

On replace donc à la ligne 85 `'\n'` par `"\n"`.

Le code compile, on peut donc regarder de plus près ce qui est faux à l'exécution.

Premièrement, on voit que `Decode` déclenche une erreur s'il n'y a pas d'erreur: il faut donc remplacer `if err == nil` par `if err != nil`.

Dans la fonction `Decrypt`, l'opération de XOR est effectuée à l'envers (probablement un mauvais copier-coller): on remplace `cfb.XORKeyStream(cipherText, plainText)` par `cfb.XORKeyStream(plainText, cipherText)`.

Enfin, on appelle la procédure `handleBase64String` dans le même processus de sorte que sa sortie soit affichée, en enlevant le `go` devant l'appel. 

## Code final

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

var bytes = []byte{53, 22, 66, 29, 75, 43, 14, 95, 34, 65, 82, 10, 23, 33, 17, 50}

const MySecret string = "\nsecret=Something_AbCdEfGhIjKlM\n"

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// This method encrypts a given text
func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	// We return the ciper text as base64
	return Encode(cipherText), nil
}

// This method decrypts a given text
func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	// We first decode the base64 input text
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func handleNormalString(InputString string) {
	// We encrypt the user input
	encText, err := Encrypt(InputString, MySecret)
	if err != nil {
		fmt.Println("error encrypting your classified text: ", err)
	}
	fmt.Println("The message was successfully encrypted: " + encText)
}

func handleBase64String(InputString string) {
	// If the input text is suspected to be an encrypted message, we decrypt it and display its content
	decText, err := Decrypt(InputString, MySecret)
	if err == nil {
		fmt.Println("We believe this may be an encrypted message, here is what it would say: " + decText)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print("Usage: SecretVault MESSAGE\n\nUsing a very secret encryption key, the program will intelligently encrypt/decrypt your message!\n")
		return
	}
	InputString := strings.Join(os.Args[1:], " ")
	InputString = strings.Replace(InputString, "\n", "", -1)

	// If the input text is suspected to be an encrypted message, we decrypt it and display its content
	if IsBase64(InputString) {
		handleBase64String(InputString)
	}
	handleNormalString(InputString)
}
```