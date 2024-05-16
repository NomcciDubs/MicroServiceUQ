package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// HealthCheck representa el estado de salud del microservicio
type HealthCheck struct {
	Status string        `json:"status"`
	Checks []CheckResult `json:"checks"`
}

// CheckResult representa el resultado de un chequeo de salud individual
type CheckResult struct {
	Name   string                 `json:"name"`
	Status string                 `json:"status"`
	Data   map[string]interface{} `json:"data"`
}

// MicroserviceVersion representa la versión del microservicio
const MicroserviceVersion = "1.0.0"

// Log representa la estructura de un registro de log
type Log struct {
	Application string `json:"application"`
	Type        string `json:"type"`
	Module      string `json:"module"`
	Timestamp   string `json:"timestamp"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
}
type LogFilter struct {
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`
	LogType   string     `json:"log_type,omitempty"`
	Page      int        `json:"page"`
	PageSize  int        `json:"page_size"`
}

// Ruta del archivo de logs

const logFilePath = "logs.txt"

// Función para ordenar los logs por fecha de creación (ascendente)
func sortLogsByCreatedAt(logs []Log) {
	// Utilizamos el algoritmo de inserción para ordenar los logs por fecha de creación
	for i := 1; i < len(logs); i++ {
		key := logs[i]
		j := i - 1
		for j >= 0 && logs[j].Timestamp > key.Timestamp {
			logs[j+1] = logs[j]
			j = j - 1
		}
		logs[j+1] = key
	}
}

// Función para manejar las solicitudes HTTP a la ruta /logs
func handleLogs(w http.ResponseWriter, r *http.Request) {
	// Leer y decodificar el JSON de los filtros
	var filter LogFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("Error al decodificar el JSON de filtros: %v", err), http.StatusBadRequest)
		return
	}

	// Establecer valores predeterminados para la paginación si no se proporcionan
	if filter.Page == 0 {
		filter.Page = 1
	}
	if filter.PageSize == 0 {
		filter.PageSize = 10
	}

	// Leer los logs del archivo
	logs, err := readLogsFromFile(logFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error al leer los logs: %v", err), http.StatusInternalServerError)
		return
	}

	// Aplicar filtros según lo especificado en el JSON de filtro
	filteredLogs := applyFilters(logs, filter)

	// Ordenar los logs por fecha de creación (ascendente)
	sortLogsByCreatedAt(filteredLogs)

	// Aplicar paginación
	paginatedLogs := paginateLogs(filteredLogs, filter.Page, filter.PageSize)

	// Codificar los logs en formato JSON y enviarlos como respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(paginatedLogs)
}

func handleLogsByApplication(w http.ResponseWriter, r *http.Request) {
	// Obtener y decodificar el nombre de la aplicación del path
	vars := mux.Vars(r)
	application := vars["application"]

	// Leer y decodificar el JSON de los filtros
	var filter LogFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("Error al decodificar el JSON de filtros: %v", err), http.StatusBadRequest)
		return
	}

	// Establecer valores predeterminados para la paginación si no se proporcionan
	if filter.Page == 0 {
		filter.Page = 1
	}
	if filter.PageSize == 0 {
		filter.PageSize = 10
	}

	// Leer los logs del archivo
	logs, err := readLogsFromFile(logFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error al leer los logs: %v", err), http.StatusInternalServerError)
		return
	}

	// Aplicar filtros según lo especificado en el JSON de filtro
	filteredLogs := applyFilters(logs, filter)

	// Filtrar por aplicación si se proporciona
	if application != "" {
		filteredLogs = filterLogsByApplication(filteredLogs, application)
	}

	// Ordenar los logs por fecha de creación (ascendente)
	sortLogsByCreatedAt(filteredLogs)

	// Aplicar paginación
	paginatedLogs := paginateLogs(filteredLogs, filter.Page, filter.PageSize)

	// Codificar los logs en formato JSON y enviarlos como respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(paginatedLogs)
}

// Función para filtrar logs por aplicación
func filterLogsByApplication(logs []Log, application string) []Log {
	var filteredLogs []Log
	for _, log := range logs {
		if log.Application == application {
			filteredLogs = append(filteredLogs, log)
		}
	}
	return filteredLogs
}

// Función para aplicar filtros a los logs
func applyFilters(logs []Log, filter LogFilter) []Log {
	filteredLogs := logs
	if filter.StartDate != nil {
		filteredLogs = filterLogsByStartDate(filteredLogs, *filter.StartDate)
	}
	if filter.EndDate != nil {
		filteredLogs = filterLogsByEndDate(filteredLogs, *filter.EndDate)
	}
	if filter.LogType != "" {
		filteredLogs = filterLogsByType(filteredLogs, filter.LogType)
	}
	return filteredLogs
}

// Función para paginar los logs
func paginateLogs(logs []Log, page, pageSize int) []Log {
	startIndex := (page - 1) * pageSize
	endIndex := startIndex + pageSize
	if startIndex < 0 {
		startIndex = 0
	}
	if endIndex > len(logs) {
		endIndex = len(logs)
	}
	return logs[startIndex:endIndex]
}

// Función para filtrar los logs por fecha de inicio
func filterLogsByStartDate(logs []Log, startDate time.Time) []Log {
	var filteredLogs []Log
	for _, log := range logs {
		logTime, _ := time.Parse("2006-01-02 15:04:05.999999", log.Timestamp)
		if logTime.Equal(startDate) || logTime.After(startDate) {
			filteredLogs = append(filteredLogs, log)
		}
	}
	return filteredLogs
}

// Función para filtrar los logs por fecha de fin
func filterLogsByEndDate(logs []Log, endDate time.Time) []Log {
	var filteredLogs []Log
	for _, log := range logs {
		logTime, _ := time.Parse("2006-01-02 15:04:05.999999", log.Timestamp)
		if logTime.Equal(endDate) || logTime.Before(endDate) {
			filteredLogs = append(filteredLogs, log)
		}
	}
	return filteredLogs
}

// Función para filtrar los logs por tipo
func filterLogsByType(logs []Log, logType string) []Log {
	var filteredLogs []Log
	for _, log := range logs {
		if log.Type == logType {
			filteredLogs = append(filteredLogs, log)
		}
	}
	return filteredLogs
}

// Función para manejar las solicitudes HTTP POST a la ruta /logs
func createLog(w http.ResponseWriter, r *http.Request) {
	// Decodificar el JSON del cuerpo de la solicitud en un objeto Log
	var log Log
	if err := json.NewDecoder(r.Body).Decode(&log); err != nil {
		http.Error(w, fmt.Sprintf("Error al decodificar el JSON del log: %v", err), http.StatusBadRequest)
		return
	}

	// Establecer la fecha y hora actual como timestamp del log
	log.Timestamp = time.Now().Format("2006-01-02 15:04:05")

	// Escribir el log en el archivo de logs
	if err := appendLogToFile(logFilePath, log); err != nil {
		http.Error(w, fmt.Sprintf("Error al escribir el log en el archivo: %v", err), http.StatusInternalServerError)
		return
	}

	// Devolver el log creado como respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(log)
}

// Función para consumir mensajes
func consumeMessages() {
	// Configurar la conexión con RabbitMQ
	conn, err := connectToRabbitMQ()
	if err != nil {
		log.Fatalf("Error al conectar con RabbitMQ: %v", err)
	}
	defer conn.Close()

	// Abrir un canal de comunicación con RabbitMQ
	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Error al abrir un canal: %v", err)
	}
	defer ch.Close()

	// Declara la cola en la que escucharás los mensajes
	q, err := ch.QueueDeclare(
		"auth_log_queue", // Nombre de la cola
		false,            // No duradera
		false,            // No eliminar cuando los consumidores se desconecten
		false,            // No exclusiva
		false,            // No esperar para procesar mensajes
		nil,              // Argumentos adicionales
	)
	if err != nil {
		log.Fatalf("Error al declarar la cola: %v", err)
	}

	// Configurar el consumidor de la cola
	msgs, err := ch.Consume(
		q.Name, // Nombre de la cola
		"",     // Identificador del consumidor (dejar en blanco para que RabbitMQ lo genere)
		true,   // Auto-ack (RabbitMQ elimina el mensaje cuando se entrega)
		false,  // No exclusiva
		false,  // No-local
		false,  // No-wait
		nil,    // Argumentos adicionales
	)
	if err != nil {
		log.Fatalf("Error al registrar el consumidor: %v", err)
	}

	// Loop para consumir mensajes
	for d := range msgs {
		// Decodificar el mensaje en un log
		var log Log
		if err := json.Unmarshal(d.Body, &log); err != nil {
			fmt.Printf("Error al decodificar el mensaje: %v\n", err)
			continue
		}

		// Guardar el log en el archivo
		if err := appendLogToFile(logFilePath, log); err != nil {
			fmt.Printf("Error al guardar el log: %v\n", err)
			continue
		}

		// Imprimir el log recibido
		fmt.Printf("Log creado: %+v\n", log)
	}
}

// Función para añadir un log al final de un archivo
func appendLogToFile(filePath string, log Log) error {
	// Abrir o crear el archivo de logs en modo de escritura, creándolo si no existe
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Codificar el log en formato JSON
	logJSON, err := json.Marshal(log)
	if err != nil {
		return err
	}

	// Escribir el log en el archivo seguido de un salto de línea
	if _, err := file.Write(append(logJSON, '\n')); err != nil {
		return err
	}

	return nil
}

// Función para leer los logs desde un archivo
func readLogsFromFile(filePath string) ([]Log, error) {
	// Abrir el archivo de logs
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Crear un scanner para leer el archivo línea por línea
	scanner := bufio.NewScanner(file)

	// Variable para almacenar los logs
	var logs []Log

	// Leer cada línea del archivo y decodificarla en un objeto Log
	for scanner.Scan() {
		var log Log
		line := scanner.Bytes()
		if err := json.Unmarshal(line, &log); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	// Verificar si hubo errores durante la lectura
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}

func connectToRabbitMQ() (*amqp.Connection, error) {
	// Intentar conectar con RabbitMQ
	for {
		conn, err := amqp.Dial("amqp://nomcci:123@rabbitmq:5672/")
		if err == nil {
			return conn, nil
		}
		log.Printf("Error al conectar con RabbitMQ: %v. Reintentando en 5 segundos...", err)
		time.Sleep(5 * time.Second)
	}
}

// HealthCheckHandler maneja las solicitudes GET a /health
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Crear una instancia de HealthCheck
	health := HealthCheck{
		Status: "UP",
		Checks: make([]CheckResult, 0),
	}

	// Agregar resultados de los chequeos de salud
	health.Checks = append(health.Checks, CheckResult{Name: "Readiness check", Status: "UP", Data: map[string]interface{}{"from": time.Now().Format(time.RFC3339)}})
	health.Checks = append(health.Checks, CheckResult{Name: "Liveness check", Status: "UP", Data: map[string]interface{}{"from": time.Now().Format(time.RFC3339)}})

	// Escribir respuesta JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// MetricsHandler maneja las solicitudes GET a /metrics
func MetricsHandler(w http.ResponseWriter, r *http.Request, registry *prometheus.Registry) {
	// Definir las métricas Prometheus
	// Por ejemplo, contador simple
	requestsTotal.Inc()

	// Crear un manejador HTTP para las métricas Prometheus
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})

	// Servir las métricas Prometheus
	handler.ServeHTTP(w, r)
}

// Registro de métricas Prometheus
var (
	requestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "myapp_requests_total",
		Help: "Total number of requests to my app.",
	})
)

// ReadyCheckHandler maneja las solicitudes GET a /health/ready
func ReadyCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Escribir respuesta JSON
	checkResult := CheckResult{Name: "Readiness check", Status: "UP", Data: map[string]interface{}{"from": time.Now().Format(time.RFC3339)}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(checkResult)
}

// LiveCheckHandler maneja las solicitudes GET a /health/live
func LiveCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Escribir respuesta JSON
	checkResult := CheckResult{Name: "Liveness check", Status: "UP", Data: map[string]interface{}{"from": time.Now().Format(time.RFC3339)}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(checkResult)
}

func main() {
	// Crear un nuevo registro Prometheus
	registry := prometheus.NewRegistry()

	// Registrar métricas en el registro Prometheus
	registry.MustRegister(requestsTotal)

	// Inicia el consumidor de RabbitMQ
	go consumeMessages()

	// Crear un enrutador utilizando gorilla/mux
	router := mux.NewRouter()

	// Definir la ruta GET /logs para obtener logs
	router.HandleFunc("/logs", handleLogs).Methods("GET")

	// Definir la ruta GET /logs/{application} para obtener logs por aplicación
	router.HandleFunc("/logs/{application}", handleLogsByApplication).Methods("GET")

	// Definir la ruta POST /logs para crear un nuevo log
	router.HandleFunc("/logs", createLog).Methods("POST")

	// Rutas de salud
	router.HandleFunc("/logs/health", HealthCheckHandler).Methods("GET")
	router.HandleFunc("/logs/health/ready", ReadyCheckHandler).Methods("GET")
	router.HandleFunc("/logs/health/live", LiveCheckHandler).Methods("GET")
	router.HandleFunc("/health", HealthCheckHandler).Methods("GET")
	router.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		MetricsHandler(w, r, registry)
	}).Methods("GET")
	// Asociar el registro Prometheus al manejador HTTP
	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	// Configura un canal para capturar las señales de interrupción
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Inicia el servidor HTTP con el enrutador
	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}
	go func() {
		log.Fatal(server.ListenAndServe())
	}()

	// Espera una señal para cerrar el programa
	<-stopChan
	fmt.Println("Aplicación detenida")
}
