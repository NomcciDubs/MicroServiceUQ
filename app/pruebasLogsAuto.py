import pytest
import requests
from app.resources import user


def test_handle_logs():
    response = requests.get('http://localhost:5000/logs', test_handle_logs)

    #assert response.status_code == (200)
    assert response.json() == {"status": "Ejecutado correctamente", "mensaje": "El log ha sido obtenido exitosamente"}

def test_handle_func():
    response = requests.get('http://localhost:5000/logs/{application}', test_handle_func)

    #assert response.status_code == (200)
    assert response.json() == {"status": "Ejecutado correctamente", "mensaje": "Se obtuvo el log desde la aplicacion"}

def test_handle_func_create():
    response = requests.post('http://localhost:5000/logs', test_handle_func_create)

    #assert response.status_code == (200)
    assert response.json() == {"status": "Ejecutado correctamente", "mensaje": "Se creo el Log de manera adecuada"}

def test_creacion_usuario():
    prueba_usuario = {"username": "Juan", "email": "prueba@gmail.com", "password": "hola123"}
    response = requests.post('http://localhost:5000/login', json=prueba_usuario)
    #assert response.status_code == (200)
    assert response.json()["mensaje"] == "Usuario registrado correctamente"

def test_login():
    prueba_login = {"username": "Juan", "password": "hola123"}
    response = requests.post('http://localhost:5000/login', json=prueba_login)
    #assert response.status_code == (200)
    assert response.json()["mensaje"] == "Usuario logueado exitosamente"

def test_logout():
    prueba_logout = {"jti": "jti"}
    response = requests.post('http://localhost:5000/logout', json=prueba_logout)
    #assert response.status_code == (200)
    assert response.json()["mensaje"] == "Usuario desconectado exitosamente"

def test_change_password():
    user.create_access_token
    prueba_change = {"old_password": "hola123", "new_password": "cambio123"}
    response = requests.post('http://localhost:5000/password', json=prueba_change)

def test_user_byid():
    user_id = 1
    response = requests.get('http://localhost:5000/users/{user_id}')
    assert response.json()["mensaje"] == "Usuario encontrado exitosamente"

def test_user_deleted():
    user_id = 1
    response = requests.delete('http://localhost:5000/users/{user_id}')
    assert response.json()["mensaje"] == "Usuario eliminado exitosamente"

# Fixture para inicializar el sistema de LOGs

# Prueba para verificar la recepción y registro de un LOG
def test_receive_and_store_log(logs_system):
    log_message = "Error: Connection timeout"
    logs_system.receive_log(log_message)
    assert logs_system.get_last_log() == log_message

# Prueba para verificar el manejo de errores al recibir un LOG vacío
def test_receive_empty_log(logs_system):
    with pytest.raises(ValueError):
        logs_system.receive_log("")

# Prueba para verificar la capacidad de escalabilidad del sistema de LOGs
def test_system_scalability(logs_system):
    # Simular la recepción de una gran cantidad de LOGs
    for i in range(1000):
        logs_system.receive_log(f"Log message {i}")
    assert logs_system.get_logs_count() == 1000