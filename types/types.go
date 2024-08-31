package types

import "time"

type UserStore interface {
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id int) (*User, error)
	CreateUser(User) error
}

type ServiceStore interface{
	GetServices(search string) ([]Service, error)
	GetServiceByName(name string) (*Service, error)
}

type Service struct{
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Availability bool   `json:"availability"`
	CreatedAt time.Time `json:"createdAt"`
}

type User struct {
	ID         int `json:"id"`
	Username      string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	OTPPrivateKey   string `json:"otpPrivateKey"`
	CreatedAt time.Time `json:"createdAt"`
}

type RegisterUserPayload struct {
	Username      string `json:"username" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=3,max=130"`
}

type LoginUserPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type OTPPayload struct {
	OTP   string `json:"otp" validate:"required,min=6,max=6"`
}