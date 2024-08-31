package user

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"something-api-2.0/config"
	"something-api-2.0/services/auth"
	"something-api-2.0/types"
	"something-api-2.0/utils"
)

type Handler struct {
	store types.UserStore
}

func NewHandler(store types.UserStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/signin", h.handleSignin).Methods("POST")
	router.HandleFunc("/register", h.handleRegister).Methods("POST")
	router.HandleFunc("/me", auth.WithJWTAuth( h.handleMe, h.store)).Methods("GET")
	router.HandleFunc("/refreshToken", h.handleRefreshToken).Methods("GET")
	router.HandleFunc("/signout", h.handleSignout).Methods("GET")
	router.HandleFunc("/otp", auth.WithJWTAuth(h.handleOTP, h.store)).Methods("POST")
}

func (h *Handler) handleSignin(w http.ResponseWriter, r *http.Request){
	// get JSON payload
	var payload types.LoginUserPayload

	if err := utils.ParseJSON(r, &payload); err != nil{
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// validate the payload
	if err := utils.Validate.Struct(payload); err != nil{
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload %v", errors))
		return
	}

	// check if user exists
	u, err := h.store.GetUserByEmail(payload.Email)

	// email not found
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("not found, invalid email or password"))
		return
	}

	// wrong password
	if !auth.ComparePasswords(u.Password, []byte(payload.Password)){
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("not found, invalid email or password"))
		return
	}

	accessToken, err := auth.CreateAccessToken([]byte(config.Envs.JWTSecret), u.ID)

	if err != nil{
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"token": accessToken})
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request){
	// get JSON payload
	var payload types.RegisterUserPayload

	if err := utils.ParseJSON(r, &payload); err != nil{
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// validate the payload
	if err := utils.Validate.Struct(payload); err != nil{
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload %v", errors))
		return
	}

	// check if the user exists
	_, err := h.store.GetUserByEmail(payload.Email)

	//user exsits
	if err == nil { 
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s already exists", payload.Email))
		return
	}

	// hash pasword to store
	hashedPassword, err := auth.HashPassword(payload.Password)

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// generate base32 encoded private key
	encodedPrivateKey, err := auth.GenAndWriteKey()

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// if user doesnt exist we create the new user
	err = h.store.CreateUser(types.User{
		Username: payload.Username,
		Email: payload.Email,
		Password: hashedPassword,
		OTPPrivateKey: encodedPrivateKey,
	})

	if err != nil { 
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, map[string]string{"privateKey": encodedPrivateKey})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request){

	// get refresh token
	refreshTokenCookie, err := r.Cookie("refreshToken")

    if err != nil {
        switch {
        case errors.Is(err, http.ErrNoCookie):
            utils.WriteError(w, http.StatusBadRequest, err)
        default:
            utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("server error"))
        }
        return
    }

	log.Println(refreshTokenCookie)

	// validate refresh token
	_, err = auth.ValidateJWT(refreshTokenCookie.Value)
	if err != nil{
		log.Printf("failed to validate token: %v", err)
		auth.PermissionDenied(w)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"token": utils.GetTokenFromRequest(r)})
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request){

	refreshTokenCookie, err := r.Cookie("refreshToken")

    if err != nil {
        switch {
        case errors.Is(err, http.ErrNoCookie):
            utils.WriteError(w, http.StatusBadRequest, err)
        default:
            utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("server error"))
        }
        return
    }

	refreshToken, err := auth.ValidateJWT(refreshTokenCookie.Value)
	if err != nil{
		log.Printf("failed to validate token: %v", err)
		auth.PermissionDenied(w)
		return
	}

	userID, err := auth.GetUserIDFromRefreshToken(refreshToken)
	if err != nil{
		log.Printf("failed to extract user id: %v", err)
		auth.PermissionDenied(w)
		return
	}

	accessToken, err := auth.CreateAccessToken([]byte(config.Envs.JWTSecret), userID)

	if err != nil{
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"token": accessToken})

}

func (h *Handler) handleSignout(w http.ResponseWriter, r *http.Request) {
    // Clear the refreshToken cookie
    refreshTokenCookie := http.Cookie{
        Name:     "refreshToken",
        Value:    "",
        Path:     "/api/v1", 
        HttpOnly: true,
        Secure:   true,  
        MaxAge:   -1,    
        Expires:  time.Unix(0, 0), 
		SameSite: http.SameSiteNoneMode,
    }

	log.Println("Clearing refresh cookie: ", refreshTokenCookie)

    http.SetCookie(w, &refreshTokenCookie)

    // Optionally, return a response to confirm sign-out
    utils.WriteJSON(w, http.StatusOK, map[string]string{"message": "Signed out successfully"})
}

func (h *Handler) handleOTP(w http.ResponseWriter, r *http.Request){
	// get JSON payload
	var payload types.OTPPayload

	userID := auth.GetUserIDFromContext(r.Context())

	if err := utils.ParseJSON(r, &payload); err != nil{
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// validate the payload
	if err := utils.Validate.Struct(payload); err != nil{
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload %v", errors))
		return
	}

	// check if user exists
	u, err := h.store.GetUserByID(userID)
	// ID not found
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("ID not found"))
		return
	}

	err = auth.ValidateOTP(u.OTPPrivateKey, payload.OTP)

	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid OTP"))
		return
	}


	refreshToken, err := auth.CreateRefreshToken([]byte(config.Envs.JWTSecret), u.ID)

	if err != nil{
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	refreshTokenCookie := http.Cookie{
        Name:     "refreshToken",
        Value:    refreshToken,
		Path:     "/api/v1",
        HttpOnly: true,
        Secure:   true,
		SameSite: http.SameSiteNoneMode,
    }

	http.SetCookie(w, &refreshTokenCookie)

	log.Println("Refresh cookie login: ", refreshTokenCookie)	

	utils.WriteJSON(w, http.StatusOK, map[string]string{"message": "Signed in successfully"})

}