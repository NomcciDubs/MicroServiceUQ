package main

import (
	"encoding/json"
	"fmt"
	"log"
	"github.com/gorilla/mux"
	"net/http"
	"sync"
	"time"
	"net/smtp"
)

// Duration es un tipo de campo personalizado para manejar duraciones en formato de cadena
type Duration struct {
	time.Duration
}

// Implementa la interfaz UnmarshalJSON para convertir la cadena en formato de duración en time.Duration
func (d *Duration) UnmarshalJSON(b []byte) error {
	var durationStr string
	if err := json.Unmarshal(b, &durationStr); err != nil {
		return err
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return err
	}
	d.Duration = duration
	return nil
}

// Implementa la interfaz MarshalJSON para convertir time.Duration en una cadena en formato JSON
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// Estructura para representar la información de un microservicio
type Microservice struct {
	Name      string   `json:"name"`
	Endpoint  string   `json:"endpoint"`
	Frequency Duration `json:"frequency"`
	Emails    []string `json:"emails"`
	Health    string   `json:"health"`
	LastCheck time.Time `json:"last_check"`
}

// Estructura para representar el monitoreo de la salud de los microservicios
type HealthMonitor struct {
	Microservices map[string]*Microservice // Mapa de nombre de microservicio a su información
	mutex         sync.Mutex
}

func (hm *HealthMonitor) RegisterMicroserviceHandler(w http.ResponseWriter, r *http.Request) {
	// Decodificar el cuerpo JSON de la solicitud para obtener los detalles del microservicio
	var microservice Microservice
	if err := json.NewDecoder(r.Body).Decode(&microservice); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar si el microservicio ya está registrado
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	if _, exists := hm.Microservices[microservice.Name]; exists {
		http.Error(w, "El microservicio ya está registrado", http.StatusBadRequest)
		return
	}

	// Agregar el microservicio al monitor de salud
	hm.Microservices[microservice.Name] = &microservice

	// Iniciar el monitoreo de salud para este microservicio
	go hm.StartHealthCheckForService(hm.Microservices[microservice.Name])

	// Responder con un mensaje de éxito
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Microservicio '%s' registrado correctamente", microservice.Name)
}

// Función para manejar la ruta /health para obtener el estado de salud de todos los microservicios
func (hm *HealthMonitor) HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Crear una estructura para almacenar los estados de salud de todos los microservicios
	health := make(map[string]string)

	// Iterar sobre todos los microservicios registrados y obtener su estado de salud
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	for name, microservice := range hm.Microservices {
		health[name] = microservice.Health
	}

	// Codificar la respuesta JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Función para manejar la ruta /health/{microservicio} para obtener el estado de salud de un microservicio específico
func (hm *HealthMonitor) MicroserviceHealthHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener el nombre del microservicio de la URL
	vars := mux.Vars(r)
	microserviceName := vars["microservice"]

	// Verificar si el microservicio existe en el monitor de salud
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	microservice, exists := hm.Microservices[microserviceName]
	if !exists {
		http.Error(w, "Microservicio no encontrado", http.StatusNotFound)
		return
	}

	// Crear una estructura para almacenar el estado de salud del microservicio
	health := map[string]string{
		"Name":   microserviceName,
		"Health": microservice.Health,
	}

	// Codificar la respuesta JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)

	// Verificar el estado del servicio y enviar un correo electrónico si no está saludable
	if microservice.Health != "UP" {
		go hm.SendEmail(microservice)
		fmt.Printf("Enviando correo")
	}
}

func (hm *HealthMonitor) SendEmail(microservice *Microservice) {
	// Detalles SMTP quemados (actualiza estos valores según tus necesidades)
	smtpHost := "sandbox.smtp.mailtrap.io"
	smtpPort := 587
	smtpUsername := "0663611ad38715"
	smtpPassword := "f50fd7467b0de7"

	// Configurar la autenticación
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)

	// Construir el mensaje de correo electrónico
	subject := "Problema con el microservicio " + microservice.Name
	body := "El microservicio " + microservice.Name + " no está funcionando correctamente."

	// Imprimir datos del microservicio
	fmt.Printf("Enviando correo para el microservicio:\n")
	fmt.Printf("Nombre: %s\n", microservice.Name)
	fmt.Printf("Endpoint: %s\n", microservice.Endpoint)
	fmt.Printf("Frecuencia: %v\n", microservice.Frequency)
	fmt.Printf("Emails: %v\n", microservice.Emails)
	fmt.Printf("Estado de salud: %s\n", microservice.Health)
	fmt.Printf("Última comprobación: %v\n", microservice.LastCheck)

	// Enviar el correo electrónico a cada dirección de correo en la lista de emails
	for _, email := range microservice.Emails {
		to := []string{email}
		msg := []byte("To: " + email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" +
			body)

		// Enviar el correo electrónico utilizando TLS
		addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
		err := smtp.SendMail(addr, auth, smtpUsername, to, msg)
		if err != nil {
			log.Printf("Error al enviar correo electrónico a %s: %s", email, err)
		} else {
			fmt.Printf("Correo enviado a %s\n", email)
		}
	}
}


// CheckHealth verifica el estado de salud de un microservicio
func CheckHealth(ms *Microservice) string {
	hm := &HealthMonitor{}
	microservice := ms
	// Realizar una solicitud HTTP al endpoint del microservicio para verificar su estado de salud
	// Por ejemplo, puedes hacer una solicitud GET al endpoint del microservicio y analizar la respuesta

	// Construir la URL del endpoint del microservicio
	url := fmt.Sprintf("%s%s", ms.Endpoint, "/health")

	// Realizar la solicitud HTTP al endpoint del microservicio
	resp, err := http.Get(url)
	if err != nil {
		// Si hay un error al realizar la solicitud, consideramos que el microservicio está "DOWN"
		fmt.Printf("Error al acceder a %s: %s\n", url, err.Error())
		go hm.SendEmail(microservice)
		fmt.Printf("Enviando correo")
		return "DOWN"
	}
	defer resp.Body.Close()

	// Verificar el código de estado de la respuestahttp://localhost:5000/login/health
	if resp.StatusCode == http.StatusOK {
		// Si el código de estado es 200 OK, consideramos que el microservicio está "UP"
		return "UP"
	}

	// Si el código de estado no es 200 OK, consideramos que el microservicio está "DOWN"
	fmt.Printf("El endpoint %s responde con un estado no válido: %d\n", url, resp.StatusCode)
	return "DOWN"
}

// StartHealthCheckForService inicia el monitoreo de salud de un microservicio
func (hm *HealthMonitor) StartHealthCheckForService(ms *Microservice) {
	// Ciclo infinito para realizar verificaciones periódicas del estado de salud del microservicio
	for {
		// Realizar verificación del estado de salud del microservicio
		health := CheckHealth(ms)

		// Actualizar el estado de salud del microservicio en el monitor de salud
		hm.mutex.Lock()
		ms.Health = health
		ms.LastCheck = time.Now()
		hm.mutex.Unlock()

		// Esperar la frecuencia definida antes de la próxima verificación
		time.Sleep(ms.Frequency.Duration)
	}
}

func main() {
	// Inicializa el monitor de salud
	healthMonitor := &HealthMonitor{
		Microservices: make(map[string]*Microservice),
	}

	// Crea un enrutador HTTP utilizando gorilla/mux
	router := mux.NewRouter()

	// Define las rutas y los controladores correspondientes
	router.HandleFunc("/register", healthMonitor.RegisterMicroserviceHandler).Methods("POST")
	router.HandleFunc("/health", healthMonitor.HealthHandler).Methods("GET")
	router.HandleFunc("/health/{microservice}", healthMonitor.MicroserviceHealthHandler).Methods("GET")
	

	// Iniciar la obtención de estado de salud para todos los microservicios registrados
	for _, ms := range healthMonitor.Microservices {
		go healthMonitor.StartHealthCheckForService(ms)
	}

	// Inicia el servidor HTTP
	fmt.Println("Server started at http://0.0.0.0:8088")
	http.ListenAndServe(":8088", router)
}
