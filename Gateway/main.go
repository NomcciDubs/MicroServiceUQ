package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	amqp "github.com/rabbitmq/amqp091-go"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type UpdateRequest struct {
	UserSecurity UserSecurity `json:"userSecurity"`
	UserProfile  UserProfile  `json:"userProfile"`
}

type UpdateResponse struct {
	SecurityResponse string `json:"securityResponse"`
	ProfileResponse  string `json:"profileResponse"`
}

type UserSecurity struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
type UserProfile struct {
	UserID              string   `json:"userId"`
	Nickname            string   `json:"nickname"`
	PersonalPageURL     string   `json:"personalPageUrl,omitempty"`
	IsContactInfoPublic bool     `json:"isContactInfoPublic"`
	MailingAddress      string   `json:"mailingAddress"`
	Biography           string   `json:"biography,omitempty"`
	Organization        string   `json:"organization,omitempty"`
	Country             string   `json:"country,omitempty"`
	SocialLinks         []string `json:"socialLinks,omitempty"`
}

type Log struct {
	Application string `json:"application"`
	Type        string `json:"type"`
	Module      string `json:"module"`
	Timestamp   string `json:"timestamp"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
}

const (
	SecurityServiceURL    = "http://web:5000"
	RabbitMQURL           = "amqp://nomcci:123@rabbitmq:5672/"
	ExchangeName          = ""
	RoutingKey            = "auth_log_queue"
	UserProfileServiceURL = "http://userprofilemanager:5055"
)

func sendLogToRabbitMQ(logData Log) error {
	// Codificar el logData en formato JSON
	body, err := json.Marshal(logData)
	if err != nil {
		return err
	}

	// Establecer la conexión con RabbitMQ
	conn, err := amqp.Dial(RabbitMQURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Crear un canal
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	// Publicar el mensaje en RabbitMQ
	err = ch.Publish(
		"",
		"auth_log_queue",
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		})
	if err != nil {
		return err
	}

	return nil
}

func AuthenticateUser(w http.ResponseWriter, r *http.Request) {
	// Parsear los datos de la solicitud
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Obtener los datos de usuario y contraseña del formulario
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	// Construir la solicitud al servicio de autenticación
	authURL := SecurityServiceURL + "/login"
	reqBody := url.Values{}
	reqBody.Set("username", username)
	reqBody.Set("password", password)

	// Realizar la solicitud POST al servicio de autenticación
	resp, err := http.PostForm(authURL, reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Leer la respuesta del servicio de autenticación
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parsear la respuesta del servicio de autenticación
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extraer el token JWT de la respuesta
	accessToken, ok := response["access_token"].(string)
	if !ok {
		http.Error(w, "No se pudo obtener el token de acceso", http.StatusInternalServerError)
		return
	}

	// Devolver el token JWT en el encabezado de la respuesta HTTP
	w.Header().Set("Authorization", "Bearer "+accessToken)

	if resp.StatusCode == http.StatusOK {
		// Crear la estructura de log
		logData := Log{
			Application: "api_gateway",
			Type:        "user_login_gateway",
			Module:      "user_management",
			Timestamp:   time.Now().Format(time.RFC3339),
			Summary:     "User login",
			Description: "User '" + username + "' has logged in.",
		}

		// Enviar el log a RabbitMQ
		if err := sendLogToRabbitMQ(logData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Enviar la respuesta de vuelta al cliente
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	// Decodificar el cuerpo de la solicitud en una estructura

	var requestData UserSecurity
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Construir la solicitud al servicio de registro de usuario
	registerURL := SecurityServiceURL + "/users"
	reqBody, err := json.Marshal(requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Realizar la solicitud POST al servicio de registro de usuario
	resp, err := http.Post(registerURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Si el registro es exitoso, enviar el log a RabbitMQ
	if resp.StatusCode == http.StatusCreated {
		// Crear la estructura de log
		logData := Log{
			Application: "api_gateway",
			Type:        "user_registration",
			Module:      "user_management",
			Timestamp:   time.Now().Format(time.RFC3339),
			Summary:     "User registration",
			Description: "User '" + requestData.Username + "' has been registered.",
		}

		// Enviar el log a RabbitMQ
		if err := sendLogToRabbitMQ(logData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Leer la respuesta del servicio de registro de usuario
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enviar la respuesta de vuelta al cliente
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logError("updateHandler", "Decoding Request", err.Error())
		returnError(w, http.StatusBadRequest, err)
		return
	}

	// Extracting data for UserSecurity
	userSecurity := UserSecurity{
		Username: req["username"].(string),
		Email:    req["email"].(string),
		Password: req["password"].(string),
	}

	// Extracting data for UserProfile
	userID := params["userid"]
	userProfile := UserProfile{
		UserID:              userID,
		Nickname:            req["username"].(string),
		IsContactInfoPublic: req["isContactInfoPublic"].(bool),
		MailingAddress:      req["email"].(string),
		PersonalPageURL:     req["personalPageUrl"].(string),
		Biography:           req["biography"].(string),
		Organization:        req["organization"].(string),
		Country:             req["country"].(string),
		SocialLinks:         toStringSlice(req["socialLinks"]),
	}

	// Log the UserProfile object before sending it to the UserProfileService
	log.Printf("Sending UserProfile object to UserProfileService: %+v\n", userProfile)

	securityResp, err := updateSecurity(userID, userSecurity)
	if err != nil {
		logError("updateHandler", "Updating Security", err.Error())
		returnError(w, http.StatusInternalServerError, err)
		return
	}

	profileResp, err := updateProfile(userID, userProfile)
	if err != nil {
		logError("updateHandler", "Updating Profile", err.Error())
		returnError(w, http.StatusInternalServerError, err)
		return
	}

	// Log exitoso
	logSuccess("update_Handler_Gateway", "User Updated Successfully", fmt.Sprintf("User %s updated successfully", userID))

	resp := UpdateResponse{
		SecurityResponse: securityResp,
		ProfileResponse:  profileResp,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func updateSecurity(userID string, security UserSecurity) (string, error) {
	url := strings.Join([]string{SecurityServiceURL, "users", userID}, "/")
	return httpPut(url, security)
}

func updateProfile(userID string, profile UserProfile) (string, error) {
	url := strings.Join([]string{UserProfileServiceURL, "api", "UserProfile", userID}, "/")
	return httpPut(url, profile)
}

func httpPut(url string, data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-OK response status code: %d", resp.StatusCode)
	}

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(responseBody), nil
}

func returnError(w http.ResponseWriter, status int, err error) {
	errorResp := ErrorResponse{Error: err.Error()}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResp)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	userID := params["userid"]

	// Get UserSecurity data
	securityURL := fmt.Sprintf("%s/users/%s", SecurityServiceURL, userID)
	securityData, err := httpGet(securityURL)
	if err != nil {
		logError("getUserHandler", "Getting Security", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	security, ok := securityData.(map[string]interface{})
	if !ok || security == nil {
		logError("getUserHandler", "Parsing Security", "Error parsing security data")
		http.Error(w, "Error parsing security data", http.StatusInternalServerError)
		return
	}
	userSecurity := UserSecurity{
		Username: getStringFromMap(security, "username"),
		Email:    getStringFromMap(security, "email"),
		Password: getStringFromMap(security, "password"),
	}

	// Get UserProfile data
	profileURL := fmt.Sprintf("%s/api/UserProfile/%s", UserProfileServiceURL, userID)
	profileData, err := httpGet(profileURL)
	if err != nil {
		logError("getUserHandler", "Getting Profile", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile, ok := profileData.(map[string]interface{})
	if !ok || profile == nil {
		logError("getUserHandler", "Parsing Profile", "Error parsing profile data")
		http.Error(w, "Error parsing profile data", http.StatusInternalServerError)
		return
	}
	userProfile := UserProfile{
		UserID:              getStringFromMap(profile, "userId"),
		Nickname:            getStringFromMap(profile, "nickname"),
		PersonalPageURL:     getStringFromMap(profile, "personalPageUrl"),
		IsContactInfoPublic: getBoolFromMap(profile, "isContactInfoPublic"),
		MailingAddress:      getStringFromMap(profile, "mailingAddress"),
		Biography:           getStringFromMap(profile, "biography"),
		Organization:        getStringFromMap(profile, "organization"),
		Country:             getStringFromMap(profile, "country"),
		SocialLinks:         toStringSlice(profile["socialLinks"]),
	}

	// Combine responses
	response := struct {
		UserSecurity UserSecurity `json:"userSecurity"`
		UserProfile  UserProfile  `json:"userProfile"`
	}{
		UserSecurity: userSecurity,
		UserProfile:  userProfile,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getStringFromMap(data map[string]interface{}, key string) string {
	if value, ok := data[key]; ok && value != nil {
		return fmt.Sprintf("%v", value)
	}
	return ""
}

func getBoolFromMap(data map[string]interface{}, key string) bool {
	if value, ok := data[key]; ok && value != nil {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
	}
	return false
}

func httpGet(url string) (interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var responseBody interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return nil, err
	}

	return responseBody, nil
}

func toStringSlice(data interface{}) []string {
	if data == nil {
		return nil
	}
	if slice, ok := data.([]interface{}); ok {
		result := make([]string, len(slice))
		for i, v := range slice {
			result[i] = fmt.Sprint(v)
		}
		return result
	}
	return nil
}
func logError(module, summary, description string) {
	logData := Log{
		Application: "api_gateway",
		Type:        "Error",
		Module:      module,
		Timestamp:   time.Now().Format(time.RFC3339),
		Summary:     summary,
		Description: description,
	}
	err := sendLogToRabbitMQ(logData)
	if err != nil {
		log.Println("Error sending log to RabbitMQ:", err)
	}
}

func logSuccess(module, summary, description string) {
	logData := Log{
		Application: "api_gateway",
		Type:        "Success",
		Module:      module,
		Timestamp:   time.Now().Format(time.RFC3339),
		Summary:     summary,
		Description: description,
	}
	err := sendLogToRabbitMQ(logData)
	if err != nil {
		log.Println("Error sending log to RabbitMQ:", err)
	}
}
func main() {
	router := mux.NewRouter()

	router.HandleFunc("/auth/login", AuthenticateUser).Methods("POST")
	router.HandleFunc("/user/register", RegisterUser).Methods("POST")
	router.HandleFunc("/user/{userid}", updateHandler).Methods("PUT")
	router.HandleFunc("/user/{userid}", getUserHandler).Methods("GET")

	// Configurar el servidor HTTP
	port := os.Getenv("PORT")
	if port == "" {
		port = "8180"
	}
	log.Printf("Servidor escuchando en el puerto %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
