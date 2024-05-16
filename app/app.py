from datetime import datetime

from flask import Flask, jsonify
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_bcrypt import check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
import pika
import json

app = Flask(__name__)



# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://nomcci:123@postgres/reto2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de Flask-Mail
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '0663611ad38715'
app.config['MAIL_PASSWORD'] = 'f50fd7467b0de7'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Configuración de Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = '0ef7b2a325bf7122e7381af5ef5e1dfca17fb327142cd386018efe7649f00c04'

# Configuración de Flask-RESTful
api = Api(app)

# Configuración de Flask-SQLAlchemy
db = SQLAlchemy(app)

# Configuración de Flask-Migrate
migrate = Migrate(app, db)

# Configuración de Flask-Bcrypt
bcrypt = Bcrypt(app)

# Configuración de Flask-JWT-Extended
jwt = JWTManager(app)

# Configuración de Flask-Mail
mail = Mail(app)

# Inicialización de SQLAlchemy
db.init_app(app)

class UserModel(db.Model):
    start_time = datetime.now()
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    print("El modelo UserModel se ha importado correctamente 1.")
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def json(self):
        return {'id': self.id, 'username': self.username, 'email': self.email}

    def send_email(subject, recipient, body):
        try:
            msg = Message(subject=subject, recipients=[recipient], body=body)
            mail.send(msg)
            return True  # Envío exitoso
        except Exception as e:
            print(f"Error sending email: {e}")
            return False

    def publish_log_message(log_data):
        try:
            credentials = pika.PlainCredentials('nomcci', '123')
            connection = pika.BlockingConnection(pika.ConnectionParameters(host='rabbitmq', credentials=credentials))
            channel = connection.channel()

            # Declara la cola
            channel.queue_declare(queue='auth_log_queue')

            # Define el mensaje que se enviará
            log_message = {
                "application": log_data.get("application", ""),
                "type": log_data.get("type", ""),
                "module": log_data.get("module", ""),
                "timestamp": str(datetime.now()),
                "summary": log_data.get("summary", ""),
                "description": log_data.get("description", "")
            }

            # Publica el mensaje en la cola
            channel.basic_publish(exchange='',
                                  routing_key='auth_log_queue',
                                  body=json.dumps(log_message))
            print(" [x] Sent %r" % log_message)

        except Exception as e:
            print(f"Error al enviar el mensaje: {e}")

        finally:
            # Cierra la conexión con RabbitMQ
            connection.close()

    def publish_register_message(user_data):
        try:
            credentials = pika.PlainCredentials('nomcci', '123')
            connection = pika.BlockingConnection(pika.ConnectionParameters(host='rabbitmq', credentials=credentials))
            channel = connection.channel()

            # Declara la nueva cola
            channel.queue_declare(queue='register_queue', durable=True)

            # Define el mensaje que se enviará
            user_profile = {
                "UserId": user_data.get("Id", ""),
                "Nickname": user_data.get("Nickname", ""),
                "MailingAddress": user_data.get("Email", ""),

            }

            # Publica el mensaje en la cola
            channel.basic_publish(exchange='',
                                  routing_key='register_queue',
                                  body=json.dumps(user_profile))
            print(" [x] Sent %r" % user_profile)

        except Exception as e:
            print(f"Error al enviar el mensaje: {e}")

        finally:
            # Cierra la conexión con RabbitMQ
            connection.close()

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def search_by_username(cls, username, page, per_page):
        return cls.query.filter(cls.username.ilike(f'%{username}%')).paginate(page=page, per_page=per_page)

with app.app_context():
    db.create_all()

@app.route('/get_tables', methods=['GET'])
def get_tables():
    # Obtener las tablas
    tables_query = db.engine.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public';
    """)

    # Imprimir los nombres de las tablas
    tables = tables_query.fetchall()
    table_names = [table[0] for table in tables]

    return jsonify({'tables': table_names})
if __name__ == '__main__':

    from resources.user import (
        UserRegister, UserLogin, UserLogout, TokenRefresh,
        ChangePassword, ForgotPassword, ResetPassword, UserSearch, User, LoginHealthCheck, UserRegisterHealth,
        TokenRefreshHealth, ChangePasswordHealth, ForgotPasswordHealth, ResetPasswordHealth, UserSearchHealth,
        HealthCheck, HealthCheckReady, HealthCheckLive, Metrics
)
    try:
        with app.app_context():
            db.create_all()
    except Exception as e:
        print(f"Error al crear las tablas: {str(e)}")

    api.add_resource(UserRegister, '/users')
    api.add_resource(UserLogin, '/login')
    api.add_resource(UserLogout, '/logout')
    api.add_resource(TokenRefresh, '/refresh')
    api.add_resource(ChangePassword, '/password')
    api.add_resource(ForgotPassword, '/forgotpassword')
    api.add_resource(ResetPassword, '/restored')
    api.add_resource(UserSearch, '/users/searched')
    api.add_resource(User, '/users/<int:user_id>', endpoint='user_by_id')
    api.add_resource(User, '/users/<int:user_id>', endpoint='delete_user')
    api.add_resource(User, '/users/<int:user_id>', endpoint='update_user')
    api.add_resource(LoginHealthCheck, '/login/health')
    api.add_resource(UserRegisterHealth, '/users/health')
    api.add_resource(TokenRefreshHealth, '/refresh/health')
    api.add_resource(ChangePasswordHealth, '/password/health')
    api.add_resource(ForgotPasswordHealth, '/forgotpassword/health')
    api.add_resource(ResetPasswordHealth, '/restored/health')
    api.add_resource(UserSearchHealth, '/users/searched/health')
    api.add_resource(HealthCheck, '/health')
    api.add_resource(HealthCheckReady, '/health/ready')
    api.add_resource(HealthCheckLive, '/health/live')
    api.add_resource(Metrics, '/metrics')


    app.run(host='0.0.0.0', port=5000, debug=True)

