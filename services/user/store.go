package user

import (
	"database/sql"
	"fmt"
	"log"

	"something-api-2.0/types"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store{
	return &Store{db: db}
}

func (s *Store) GetUserByEmail(email string) (*types.User, error){
	rows, err := s.db.Query("SELECT * FROM users WHERE email = ?", email)

	if err != nil {
		return nil, err
	}

	u := new(types.User)
	for rows.Next(){
		u, err = scanRowIntoUser(rows)
		if err != nil{
			return nil, err
		}
	}

	if u.ID == 0{
		return nil, fmt.Errorf("user not found")
	}

	return u, nil
}

func scanRowIntoUser(rows *sql.Rows) (*types.User, error){
	user := new(types.User)
	err := rows.Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.OTPPrivateKey,
		&user.CreatedAt,
	)

	if err != nil{
		return nil, err
	}

	return user, nil
}

func (s *Store) GetUserByID(id int) (*types.User, error){
	rows, err := s.db.Query("SELECT * FROM users WHERE id = ?", id)

	if err != nil {
		return nil, err
	}

	u := new(types.User)
	for rows.Next(){
		u, err = scanRowIntoUser(rows)
		if err != nil{
			return nil, err
		}
	}

	if u.ID == 0{
		return nil, fmt.Errorf("user not found")
	}

	return u, nil
}

func (s *Store) CreateUser(user types.User) error{
	log.Println(user.OTPPrivateKey)
	_, err := s.db.Exec("INSERT INTO users (username, email, password, otp_private_key) VALUES (?,?,?,?)", user.Username, user.Email, user.Password, user.OTPPrivateKey)

	if err != nil {
		return err
	}
	
	return nil
}