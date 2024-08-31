package service

import (
	"database/sql"
	"fmt"

	"something-api-2.0/types"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store{
	return &Store{db: db}
}

func (s *Store) GetServices(search string) ([]types.Service, error) {

	searchPattern := "%" + search + "%"

	rows, err := s.db.Query("SELECT * FROM services WHERE service_name LIKE ?", searchPattern)

	if err != nil {
		return nil, err
	}

	filteredServices := []types.Service{}
	for rows.Next(){
		s, err := scanRowsIntoServices(rows)
		if err != nil{
			return nil, err
		}

		filteredServices = append(filteredServices, *s)
	}

	return filteredServices, nil
}

func (s *Store) GetServiceByName(name string) (*types.Service, error){

	rows, err := s.db.Query("SELECT * FROM services WHERE service_name = ?", name)

	if err != nil {
		return nil, err
	}

	service := new(types.Service)
	for rows.Next(){
		service, err = scanRowsIntoServices(rows)
		if err != nil{
			return nil, err
		}
	}

	if service.ID == 0{
		return nil, fmt.Errorf("service not found")
	}


	return service, nil
}

func scanRowsIntoServices(rows *sql.Rows) (*types.Service, error) {
	service := new(types.Service)
	err := rows.Scan(
		&service.ID,
		&service.Name,
		&service.Availability,
		&service.CreatedAt,
	)

	if err != nil{
		return nil, err
	}

	return service, nil
}