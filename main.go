package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"log"
	"os"
)

//Esta funcion genera un par de llaves, y retorna dos valors
// llave privada y llave publica
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	keyPair, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("Error al generar par de llaves %v", err)
	}
	return keyPair, &keyPair.PublicKey
}

// Esta funcion encripta el mensaje con la clave publica
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		log.Fatal(err)
	}
	return ciphertext
}

// Esta funcion desencripta el mensaje con clave Privada
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return plaintext
}

//Esta funcion firma el mensaje con la llave publica,
// retorna la firma en byte para poder ser guardad en un
//archivo
func SignatureWithPrivateKey(message []byte, priv *rsa.PrivateKey) []byte {
	newHash := crypto.SHA512
	pssh := newHash.New()
	pssh.Write(message)
	hashed := pssh.Sum(nil)

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	signature, err := rsa.SignPSS(rand.Reader, priv, newHash, hashed, &opts)
	if err != nil {
		log.Fatalf("Error Signature %v", err)
	}
	return signature
}

//Esta funcion verifica la autenticidad del mensaje, en caso de
//que el mensaje sea adulterado retornamos un error
func VerifyWithPublicKey(message []byte, signature []byte, publi *rsa.PublicKey) error {
	newHash := crypto.SHA512
	pssh := newHash.New()
	pssh.Write(message)
	hashed := pssh.Sum(nil)

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	err := rsa.VerifyPSS(publi, newHash, hashed, signature, &opts)
	return err
}

func main() {

	privateKey, publicKey := GenerateKeyPair(2048)
	//Definimos el mensaje que vamos a encriptar
	message := []byte("Esto es una prueba")
	//Llamamos a la funcion pasandole el mensaje original y
	//la llave publica
	messageEncrypted := EncryptWithPublicKey(message, publicKey)
	//LLamamos a la funcion para desencriptar el mensaje,
	//le pasamos como parametro el mensaje previamente encriptado
	//y la clave privada
	message = DecryptWithPrivateKey(messageEncrypted, privateKey)
	//Imprimimos el mensaje
	log.Printf("Mensaje Desencriptado => %s\n\r", message)

	//llamamos a la funcion para generar la firma
	signedMessage := SignatureWithPrivateKey(message, privateKey)

	//LLamamos a la funcion para verificar la autenticidad del
	//mensaje, la funcion devuelve un error si el mensaje fue
	//adulterado, para esta funcione necesitamos
	// 1) Mensaje
	// 2) Firma
	// 3) Clave Publica
	err := VerifyWithPublicKey(message, signedMessage, publicKey)
	if err != nil {
		log.Println("El mensaje esta adulterado")
		os.Exit(1)
	}
	log.Println("El mensaje esta correcto")

}
