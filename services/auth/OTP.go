package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"log"
	"math"
	"strconv"
	"time"

	"something-api-2.0/config"
)

func ValidateOTP(sharedSecretEncoded string, inputOTPstring string) error {

	sharedSecret, err := base32.StdEncoding.DecodeString(sharedSecretEncoded)
	if err != nil {
		log.Fatalf("Key Decoding Error: %s", err)
	}

	inputOTP, err := strconv.ParseInt(inputOTPstring, 10, 32)
	if err != nil {
		return fmt.Errorf("error converting OTP string to int")
	}

	if getTOTP(sharedSecret) == int(inputOTP) {
		return nil
	} else {
		return fmt.Errorf("invalid or expired OTP")
	}
}

func getTOTP(key []byte) int {
	mac := hmac.New(sha1.New, key)

	timeStamp := time.Now().Unix() / 30
	timeStampBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timeStampBytes[i] = byte(timeStamp & 0xff)
		timeStamp = timeStamp >> 8
	}

	mac.Write(timeStampBytes)
	macResult := mac.Sum(nil)

	offset := int(macResult[len(macResult)-1]) & 0xf
	truncatedResult := int(macResult[offset]&0x7f)<<24 |
		int(macResult[offset+1]&0xff)<<16 |
		int(macResult[offset+2]&0xff)<<8 |
		int(macResult[offset+3]&0xff)
	return truncatedResult % int(math.Pow10(6))
}

func GenAndWriteKey() (string, error) {
	key := make([]byte, config.Envs.OTPKeyLength)
    _, err := rand.Read(key)

    if err != nil {
		return "", err
    }

	encodedKey := base32.StdEncoding.EncodeToString(key)
	
	return encodedKey, nil
}
