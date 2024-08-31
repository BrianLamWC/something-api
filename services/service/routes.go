package service

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"something-api-2.0/services/auth"
	"something-api-2.0/types"
	"something-api-2.0/utils"
)

type Handler struct {
	store types.ServiceStore
	userStore types.UserStore
}

func NewHandler(store types.ServiceStore, userStore types.UserStore) *Handler {
	return &Handler{store: store, userStore: userStore}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/services", auth.WithJWTAuth(h.getServices, h.userStore)).Methods("GET")
	router.PathPrefix("/images").Handler(http.StripPrefix("/api/v1/images", http.FileServer(http.Dir("./services/serviceImages"))))
}

func (h *Handler) getServices(w http.ResponseWriter, r *http.Request){
	hasSearch := r.URL.Query().Has("search")
	hasServiceName := r.URL.Query().Has("name")

	if hasSearch {
		search := r.URL.Query().Get("search")

		//fmt.Printf("%s search value: %s\n", r.URL, search)
	
		filteredServices, err := h.store.GetServices(search)

		if err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	
		//fmt.Println("Services:", filteredServices)
	
		utils.WriteJSON(w, http.StatusOK, filteredServices)

		return
	}

	if hasServiceName {
		name := r.URL.Query().Get("name")
		service, err := h.store.GetServiceByName(name)

		//service does not exist
		if err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err)
			return
		}

		utils.WriteJSON(w, http.StatusOK, *service)
		return
	}

	utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("no params"))

}

// func (h *Handler) handleServiceImages(w http.ResponseWriter, r *http.Request){

// }
