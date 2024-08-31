package api

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"something-api-2.0/services/service"
	"something-api-2.0/services/user"
)

type APIServer struct {
	addr string
	db   *sql.DB
}

func NewAPIServer(addr string, db *sql.DB) *APIServer{
	return &APIServer{
		addr: addr,
		db: db,
	}
}

func (s *APIServer) Run() error {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/api/v1").Subrouter()

	userStore := user.NewStore(s.db)
	userHandler := user.NewHandler(userStore)
	userHandler.RegisterRoutes(subrouter)

	serviceStore := service.NewStore(s.db)
	serviceHandler := service.NewHandler(serviceStore, userStore)
	serviceHandler.RegisterRoutes(subrouter)

	// Configure CORS
	corsOptions := handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:5173", "https://something-dsf5tlrk1-brianlamwcs-projects.vercel.app"}), // Replace with your frontend's address
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
		handlers.AllowCredentials(),
	)
	
	log.Println("Listening on", s.addr)
	
	return http.ListenAndServe(s.addr, corsOptions(router))
}
