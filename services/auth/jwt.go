package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"something-api-2.0/config"
	"something-api-2.0/types"
	"something-api-2.0/utils"
)

type contextKey string

const UserKey contextKey = "userID"

func CreateRefreshToken(secret []byte, userID int) (string, error) {

	expiration := time.Second * time.Duration(config.Envs.RefreshTokenExpirationInSeconds) // get duration in seconds

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": strconv.Itoa(userID),
		"exp": time.Now().Add(expiration).Unix(), // add to the current time this token was created
	})

	tokenString, err := token.SignedString(secret)

	if err != nil{
		return "", err
	}

	return tokenString, nil
}

func CreateAccessToken(secret []byte, userID int) (string, error) {

	expiration := time.Second * time.Duration(config.Envs.AccessTokenExpirationInSeconds) // get duration in seconds

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": strconv.Itoa(userID),
		"exp": time.Now().Add(expiration).Unix(), // add to the current time this token was created
	})

	tokenString, err := token.SignedString(secret)

	if err != nil{
		return "", err
	}

	return tokenString, nil
}

func WithJWTAuth(handlerFunc http.HandlerFunc, store types.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		// get the token from the user request
		tokenString := utils.GetTokenFromRequest(r)
		// validate JWT 
		token, err := ValidateJWT(tokenString)
		if err != nil{
			log.Printf("failed to validate token: %v", err)
			PermissionDenied(w)
			return
		}

		// if !token.Valid{
		// 	log.Printf("invalid token")
		// 	permissionDenied(w)
		// 	return
		// }

		if _, ok := token.Claims.(jwt.MapClaims); !ok{
			log.Printf("invalid token")
			PermissionDenied(w)
			return
		}

		// fetch the userID from the DB (userID in the token)

		claims := token.Claims.(jwt.MapClaims)
		userIDStr := claims["userID"].(string)
		userID, _ := strconv.Atoi(userIDStr)

		u, err := store.GetUserByID(userID)
		if err != nil{
			log.Printf("failed to get user by id %v", err)
			PermissionDenied(w)
			return
		}


		// Add the user to the context
		ctx := r.Context()
		ctx = context.WithValue(ctx, UserKey, u.ID)
		r = r.WithContext(ctx)

		// Call the function if the token is valid
		handlerFunc(w, r)
		// set context "userID" to the user ID
	}
}

func ValidateJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok{
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(config.Envs.JWTSecret), nil
	})
}

func PermissionDenied(w http.ResponseWriter){
	utils.WriteError(w, http.StatusForbidden, fmt.Errorf("permission denied"))
}

func GetUserIDFromContext(ctx context.Context) int {
	userID, ok := ctx.Value(UserKey).(int)
	if !ok {
		return -1
	}

	return userID
}

func GetUserIDFromRefreshToken(refreshToken *jwt.Token)(int, error){

	claims, ok := refreshToken.Claims.(jwt.MapClaims)
    if !ok || !refreshToken.Valid {
        return 0, fmt.Errorf("invalid token claims")
    }

    userIDStr, ok := claims["userID"].(string)
    if !ok {
        return 0, fmt.Errorf("userID not found in token claims")
    }

    userID, err := strconv.Atoi(userIDStr)
    if err != nil {
        return 0, fmt.Errorf("invalid userID in token claims")
    }

	return userID, nil
}