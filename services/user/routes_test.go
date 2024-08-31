package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"something-api-2.0/types"
)

func TestUserServiceHandlers(t *testing.T){
	userStore := &mockUserStore{}
	handler := NewHandler(userStore)

	t.Run("should pass if user payload is invalid", func( t *testing.T){
		payload := types.RegisterUserPayload{
			Username : "user",
			Email: "invalid@gmail.com",
			Password: "qwerty",
		}

		marshalled, _:= json.Marshal(payload)

		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(marshalled))

		if err != nil{
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router := mux.NewRouter()

		router.HandleFunc("/register", handler.handleRegister)
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest{
			t.Errorf("expected status code %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("should pass if user payload is valid", func (t *testing.T)  {
		payload := types.RegisterUserPayload{
			Username : "user",
			Email: "user@gmail.com",
			Password: "qwerty",
		}

		marshalled, _:= json.Marshal(payload)

		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(marshalled))

		if err != nil{
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router := mux.NewRouter()

		router.HandleFunc("/register", handler.handleRegister)
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated{
			t.Errorf("expected status code %d, got %d", http.StatusCreated, rr.Code)
		}
	})
}

type mockUserStore struct{}

func (m *mockUserStore) GetUserByEmail(email string) (*types.User, error) {
	return nil, fmt.Errorf("user not found")
}

func (m *mockUserStore) GetUserByID(id int) (*types.User, error){
	return nil, nil
}

func (m *mockUserStore) CreateUser(types.User) error  {
	return nil
}