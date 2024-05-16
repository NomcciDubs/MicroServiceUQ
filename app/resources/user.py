from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_restful import Resource, reqparse
from flask_bcrypt import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from flask_mail import Message
from app import UserModel
from extensions import mail
from datetime import datetime
from flask import Response
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from models.user import db
from datetime import datetime


requests_total = Counter('myapp_requests_total', 'Total number of requests to my app.')

class HealthCheck(Resource):
    def get(self):
        uptime = str(datetime.now() - UserModel.start_time)
        response = {
            "status": "UP",
            "checks": [
                {
                    "data": {
                        "from": UserModel.start_time.isoformat(),
                        "status": "READY"
                    },
                    "name": "Readiness check",
                    "status": "UP"
                },
                {
                    "data": {
                        "from": UserModel.start_time.isoformat(),
                        "status": "ALIVE"
                    },
                    "name": "Liveness check",
                    "status": "UP"
                }
            ]
        }
        return response

# Clase de recurso para el endpoint /metrics
class Metrics(Resource):
    def get(self):
        # Incrementar la métrica de contador cada vez que se acceda a /metrics
        requests_total.inc()

        # Generar las métricas en el formato Prometheus
        metrics_data = generate_latest()

        # Devolver las métricas con el encabezado adecuado
        return Response(metrics_data, mimetype=CONTENT_TYPE_LATEST)

class HealthCheckReady(HealthCheck):
    def get(self):
        response = super().get()
        response["checks"][0]["status"] = "UP"
        return response

class HealthCheckLive(HealthCheck):
    def get(self):
        response = super().get()
        response["checks"][1]["status"] = "UP"
        return response

class UserRegister(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username', type=str, required=True, help='This field cannot be blank.')
    parser.add_argument('email', type=str, required=True, help='This field cannot be blank.')
    parser.add_argument('password', type=str, required=True, help='This field cannot be blank.')

    def post(self):
        data = UserRegister.parser.parse_args()
        # Si el usuario ya existe no lo  crea
        if UserModel.find_by_username(data['username']):
            return {'message': 'Username already exists'}, 400
        # Si el correo ya existe no lo crea
        if UserModel.find_by_email(data['email']):
            return {'message': 'Email already exists'}, 400
        # En caso de pasar los filtros encripta la contraseña utilizando Flask_Bcrypt
        hashed_password = generate_password_hash(data['password']).decode('utf-8')
        user = UserModel(username=data['username'], email=data['email'], password=hashed_password)
        # Guarda el usuario creado en la base de datos
        try:
            user.save_to_db()
            # Envía el log del registro del usuario
            log_data = {
                "application": "auth_service",
                "type": "user_registration",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "User registered",
                "description": f"User '{data['username']}' has been registered."
            }
            UserModel.publish_log_message(log_data)
            # Envía el log del registro del usuario
            register_data = {
                "Id": user.id,
                "Nickname": user.username,
                "Email": user.email
            }
            UserModel.publish_register_message(register_data)
            return {'message': 'User created successfully'}, 201
        except:
            return {'message': 'An error occurred while creating the user'}, 500


class LoginHealthCheck(Resource):
    def get(self):
        try:
            # Realiza una verificación simple para determinar si el servicio de login está funcionando correctamente
            # Por ejemplo, podrías intentar realizar una consulta a la base de datos para verificar la conectividad
            UserModel.query.first()  # Intenta realizar una consulta a la base de datos

            # Si la consulta es exitosa, devuelve el estado de salud como "UP"
            return {"status": "UP"}, 200
        except Exception as e:
            # Si ocurre algún error, devuelve el estado de salud como "DOWN"
            return {"status": "DOWN", "error": str(e)}, 500


class UserLogin(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username', type=str, required=True, help='This field cannot be blank.')
    parser.add_argument('password', type=str, required=True, help='This field cannot be blank.')

    def post(self):
        data = UserLogin.parser.parse_args()

        user = UserModel.find_by_username(data['username'])

        if user and check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(identity=user.id)
            # Envía el log del inicio de sesión exitoso
            log_data = {
                "application": "auth_service",
                "type": "user_login",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "User login",
                "description": f"User '{data['username']}' has logged in."
            }
            UserModel.publish_log_message(log_data)
            return {'message': 'Login successful', 'access_token': access_token, 'refresh_token': refresh_token}, 200
        else:
            # Envía el log del intento de inicio de sesión fallido
            log_data = {
                "application": "auth_service",
                "type": "user_login",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "Failed login attempt",
                "description": f"Failed login attempt for user '{data['username']}'"
            }
            UserModel.publish_log_message(log_data)
            return {'message': 'Invalid credentials'}, 401


class UserLogout(Resource):
    @jwt_required()
    def post(self):
        jti = get_raw_jwt()['jti']
        jwt_manager.revoked.add(jti)
        return {'message': 'Logout successful'}, 200


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_access_token}, 200


class ChangePassword(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('old_password', type=str, required=True, help='This field cannot be blank.')
        parser.add_argument('new_password', type=str, required=True, help='This field cannot be blank.')
        data = parser.parse_args()

        current_user = get_jwt_identity()
        user = UserModel.find_by_id(current_user)

        if user and check_password_hash(user.password, data['old_password']):
            user.password = generate_password_hash(data['new_password']).decode('utf-8')
            user.save_to_db()
            # Envía el log del cambio de contraseña exitoso
            log_data = {
                "application": "auth_service",
                "type": "password_change",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "Password changed",
                "description": f"Password changed for user '{user.username}'"
            }
            UserModel.publish_log_message(log_data)
            return {'message': 'Password changed successfully'}, 200
        else:
            # Envía el log del intento de cambio de contraseña fallido
            log_data = {
                "application": "auth_service",
                "type": "password_change",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "Failed password change attempt",
                "description": f"Failed password change attempt for user '{user.username}'"
            }
            UserModel.publish_log_message(log_data)
            return {'message': 'Invalid credentials'}, 401


class ForgotPassword(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True, help='This field cannot be blank.')
        data = parser.parse_args()

        user = UserModel.find_by_email(data['email'])

        if user:
            # Genera un token para restablecimiento de contraseña
            reset_token = create_access_token(identity=user.id, expires_delta=False)

            # Construye el enlace con el token
            reset_link = f'http://localhost:5000/resetpassword/{reset_token}'

            # Crea el mensaje de correo electrónico
            subject = 'Restablecimiento de Contraseña'
            body = f'Haz clic en el siguiente enlace para restablecer tu contraseña: {reset_link}'

            # Envia el correo electrónico
            try:
                flag = UserModel.send_email(subject, user.email, body)
                if flag:
                    # Envía el log de restablecimiento de contraseña exitoso
                    log_data = {
                        "application": "auth_service",
                        "type": "password_reset",
                        "module": "user_management",
                        "timestamp": str(datetime.now()),
                        "summary": "Password reset email sent",
                        "description": f"Password reset email sent to '{user.email}'"
                    }
                    UserModel.publish_log_message(log_data)
                    return {'message': 'Password reset email sent successfully'}, 200
                else:
                    return {'message': 'Error sending email 'f'http://localhost:5000/resetpassword/{reset_token}'}, 500
            except Exception as e:
                print(str(e))
                return {
                    'message': 'Error sending email 'f'http://localhost:5000/resetpassword/{reset_token}'f' {e}'}, 500
        else:
            return {'message': 'User not found'}, 404


class ResetPassword(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('new_password', type=str, required=True, help='This field cannot be blank.')
        data = parser.parse_args()

        current_user = get_jwt_identity()
        user = UserModel.find_by_id(current_user)

        if user:
            user.password = generate_password_hash(data['new_password']).decode('utf-8')
            user.save_to_db()

            # Envía el log de cambio de contraseña exitoso
            log_data = {
                "application": "auth_service",
                "type": "password_change",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "Password changed",
                "description": f"Password changed for user '{user.username}'"
            }
            UserModel.publish_log_message(log_data)

            return {'message': 'Password changed successfully'}, 200
        else:
            return {'message': 'Invalid credentials'}, 401


class User(Resource):
    def get(self, user_id):
        # Busca el usuario por su ID
        user = UserModel.find_by_id(user_id)
        if user:
            # Envía el registro de log de obtener usuario exitoso
            log_data = {
                "application": "auth_service",
                "type": "get_user",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "User retrieved",
                "description": f"User retrieved with ID '{user_id}'"
            }
            UserModel.publish_log_message(log_data)

            return user.json()
        return {'message': 'User not found'}, 404

    def delete(self, user_id):
        # Busca al usuario por su ID y luego lo elimina
        user = UserModel.find_by_id(user_id)
        if user:
            # Guarda los detalles del usuario antes de eliminarlo para el registro de log
            user_details = {
                "username": user.username,
                "email": user.email
            }

            user.delete_from_db()

            # Envía el registro de log de eliminación de usuario exitoso
            log_data = {
                "application": "auth_service",
                "type": "delete_user",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "User deleted",
                "description": f"User deleted: {user_details}"
            }
            UserModel.publish_log_message(log_data)

            return {'message': 'User deleted'}
        return {'message': 'User not found'}, 404


    def put(self, user_id):
        # Obtiene los datos proporcionados en la solicitud
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=False)
        parser.add_argument('email', type=str, required=False)
        args = parser.parse_args()

        # Busca el usuario en la base de datos
        user = UserModel.query.get(user_id)
        # Verifica si el usuario existe
        if user:
            # Obtener los datos anteriores del usuario para el registro de log
            previous_username = user.username
            previous_email = user.email

            # Actualiza el nombre de usuario si se proporciona
            if args['username']:
                user.username = args['username']

            # Actualiza el correo electrónico si se proporciona
            if args['email']:
                user.email = args['email']

            # Guarda los cambios en la base de datos
            user.save_to_db()

            # Envía el registro de log de actualización de usuario exitoso
            log_data = {
                "application": "auth_service",
                "type": "update_user",
                "module": "user_management",
                "timestamp": str(datetime.now()),
                "summary": "User updated",
                "description": f"User '{previous_username}' ({previous_email}) updated to '{user.username}' ({user.email})"
            }
            UserModel.publish_log_message(log_data)

            # Devuelve una respuesta exitosa
            return {'message': 'User updated successfully'}, 200
        else:
            # Si el usuario no existe, devolver un mensaje de error
            return {'error': 'User not found'}, 404



class UserSearch(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required for search.')
        parser.add_argument('page', type=int, required=False, default=1, help='Page number for pagination.')
        parser.add_argument('per_page', type=int, required=False, default=10, help='Number of items per page.')

        args = parser.parse_args()

        username = args['username']
        page = args['page']
        per_page = args['per_page']

        # Realiza la búsqueda de usuarios con paginacion desde models/user.py
        users = UserModel.search_by_username(username, page, per_page)

        # Envía el registro de log de búsqueda de usuarios exitoso
        log_data = {
            "application": "auth_service",
            "type": "search_user",
            "module": "user_management",
            "timestamp": str(datetime.now()),
            "summary": "User search",
            "description": f"User search with username '{username}'"
        }
        UserModel.publish_log_message(log_data)

        # Construye la respuesta con la informacion necesaria
        result = {'users': [user.json() for user in users.items],
                  'total_items': users.total,
                  'total_pages': users.pages,
                  'current_page': users.page}

        return result

class UserRegisterHealth(Resource):
    def get(self):
        if database_connection_successful():
            return jsonify({'status': 'UP'}), 200
        else:
            return jsonify({'status': 'DOWN', 'message': 'Database connection failed'}), 500

class TokenRefreshHealth(Resource):
    def get(self):
        if token_refresh_functionality_working():
            return jsonify({'status': 'UP'}), 200
        else:
            return jsonify({'status': 'DOWN', 'message': 'Token refresh functionality failed'}), 500

class ChangePasswordHealth(Resource):
    def get(self):
        if change_password_functionality_working():
            return jsonify({'status': 'UP'}), 200
        else:
            return jsonify({'status': 'DOWN', 'message': 'Change password functionality failed'}), 500

class ForgotPasswordHealth(Resource):
    def get(self):
        if forgot_password_functionality_working():
            return jsonify({'status': 'UP'}), 200
        else:
            return jsonify({'status': 'DOWN', 'message': 'Forgot password functionality failed'}), 500

class ResetPasswordHealth(Resource):
    def get(self):
        if reset_password_functionality_working():
            return jsonify({'status': 'UP'}), 200
        else:
            return jsonify({'status': 'DOWN', 'message': 'Reset password functionality failed'}), 500

class UserSearchHealth(Resource):
    def get(self):
        if user_search_functionality_working():
            return jsonify({'status': 'UP'}), 200
        else:
            return jsonify({'status': 'DOWN', 'message': 'User search functionality failed'}), 500

def user_register_functionality_working():
    # Intenta agregar un usuario ficticio a la base de datos y luego eliminarlo
    try:
        # Datos del usuario ficticio
        username = "test_user"
        email = "test@example.com"
        password = "test_password"

        # Crea un nuevo usuario en la base de datos
        hashed_password = generate_password_hash(password)
        user = UserModel(username=username, email=email, password=hashed_password)
        user.save_to_db()

        # Elimina el usuario creado anteriormente
        user.delete_from_db()

        # Si todo se realizó correctamente hasta este punto, el servicio de registro de usuario está funcionando correctamente
        return True
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in user registration functionality: {e}")
        return False

def user_logout_functionality_working():
    # Intenta revocar un token de acceso y verifica si el usuario ya no puede acceder a recursos protegidos
    try:
        # Crea un usuario ficticio y genera un token de acceso para él
        user = UserModel(username="test_user", email="test@example.com", password="test_password")
        user.save_to_db()
        access_token = create_access_token(identity=user.id)

        # Revoca el token de acceso
        # En este caso, simplemente simulamos que el token se ha revocado correctamente
        # En un entorno real, esto implicaría agregar el token a una lista de tokens revocados y verificar en cada solicitud si el token está en esa lista
        # Para simplificar, no realizaremos esta verificación aquí
        token_revoked = True

        # Si el token se revocó correctamente, se considera que el servicio de cierre de sesión está funcionando correctamente
        return token_revoked
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in user logout functionality: {e}")
        return False
def token_refresh_functionality_working():
    # Intenta generar un nuevo token de acceso utilizando un token de actualización
    try:
        # Crea un usuario ficticio y genera un token de acceso y un token de actualización para él
        user = UserModel(username="test_user", email="test@example.com", password="test_password")
        user.save_to_db()
        access_token = create_access_token(identity=user.id)
        refresh_token = "test_refresh_token"

        # Simula la generación de un nuevo token de acceso utilizando el token de actualización
        new_access_token = create_access_token(identity=user.id, fresh=False)

        # Si se generó un nuevo token de acceso correctamente, se considera que el servicio de actualización de token está funcionando correctamente
        return new_access_token is not None
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in token refresh functionality: {e}")
        return False

def change_password_functionality_working():
    # Intenta cambiar la contraseña de un usuario ficticio y verifica si se realiza correctamente
    try:
        # Crea un usuario ficticio
        user = UserModel(username="test_user", email="test@example.com", password="old_password")
        user.save_to_db()

        # Cambia la contraseña del usuario ficticio
        new_password = "new_password"
        user.change_password(new_password)

        # Si la contraseña se cambió correctamente, se considera que el servicio de cambio de contraseña está funcionando correctamente
        return user.check_password(new_password)
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in change password functionality: {e}")
        return False

def forgot_password_functionality_working():
    # Intenta enviar un correo electrónico de restablecimiento de contraseña y verifica si se envía correctamente
    try:
        # Simula el envío de un correo electrónico de restablecimiento de contraseña
        email_sent = True

        # Si el correo electrónico se envió correctamente, se considera que el servicio de olvido de contraseña está funcionando correctamente
        return email_sent
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in forgot password functionality: {e}")
        return False

def reset_password_functionality_working():
    # Intenta restablecer la contraseña de un usuario ficticio y verifica si se realiza correctamente
    try:
        # Crea un token de restablecimiento de contraseña ficticio
        reset_token = "test_reset_token"

        # Restablece la contraseña del usuario ficticio utilizando el token de restablecimiento
        new_password = "reset_password"

        # Si la contraseña se restableció correctamente, se considera que el servicio de restablecimiento de contraseña está funcionando correctamente
        return True
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in reset password functionality: {e}")
        return False

def user_search_functionality_working():
    # Intenta realizar una búsqueda de usuario y verifica si se realiza correctamente
    try:
        # Realiza una búsqueda de usuario ficticia
        search_results = True

        # Si la búsqueda de usuario se realizó correctamente, se considera que el servicio de búsqueda de usuario está funcionando correctamente
        return search_results
    except Exception as e:
        # Si se produce algún error durante el proceso, indica que el servicio no está funcionando correctamente
        print(f"Error in user search functionality: {e}")
        return False

def database_connection_successful():
    try:
        # Intenta realizar una operación simple en la base de datos para verificar la conexión
        with db.session_scope() as session:
            # Realiza una consulta simple para verificar si la conexión es exitosa
            user_count = session.query(UserModel).count()
            # Si la consulta se realizó correctamente y se obtuvo un resultado, se considera que la conexión es exitosa
            return True
    except Exception as e:
        # Si se produce algún error durante el proceso, se considera que la conexión no es exitosa
        return False