using System.Text;
using Newtonsoft.Json;
using System.Data;
using Npgsql;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using UserProfileService.Models;

namespace UserProfileService.Consumers
{
    public class RabbitMQConsumer
    {
        private readonly ConnectionFactory _rabbitMqFactory;
        private readonly NpgsqlConnection _dbConnection;
        private IConnection _connection;
        private IModel _channel;

        public RabbitMQConsumer(ConnectionFactory rabbitMQFactory, NpgsqlConnection dbConnection)
        {
            _rabbitMqFactory = rabbitMQFactory;
            _dbConnection = dbConnection;
        }

        public void StartConsuming()
        {
            ConnectAndConsumeAsync();
        }

        private async Task ConnectAndConsumeAsync()
        {
            try
            {
                Console.WriteLine("Attempting to connect to RabbitMQ...");
                _connection = _rabbitMqFactory.CreateConnection();
                _channel = _connection.CreateModel();

                _channel.QueueDeclare(queue: "register_queue", durable: true, exclusive: false, autoDelete: false, arguments: null);

                var consumer = new EventingBasicConsumer(_channel);
                consumer.Received += async (model, ea) =>
                {
                    try
                    {
                        var body = ea.Body.ToArray();
                        var message = Encoding.UTF8.GetString(body);
                        Console.WriteLine(" [x] Received {0}", message);

                        // Deserializar el mensaje JSON
                        var user_data = JsonConvert.DeserializeObject<dynamic>(message);

                        // Validar los datos recibidos
                        if (!string.IsNullOrEmpty(user_data.UserId.ToString()) &&
                            !string.IsNullOrEmpty(user_data.Nickname.ToString()) &&
                            !string.IsNullOrEmpty(user_data.MailingAddress.ToString()))
                        {
                            // Insertar el registro en la base de datos
                            await InsertUserProfileAsync(user_data.UserId.ToString(), user_data.Nickname.ToString(), user_data.MailingAddress.ToString());

                            Console.WriteLine($"Created profile for user: {user_data.Nickname}");

                            // Enviar mensaje al log
                            var logData = new Log
                            {
                                Application = "UserProfileService",
                                Type = "Info",
                                Module = "UserProfile",
                                Timestamp = DateTime.Now.ToString(),
                                Summary = "New user created",
                                Description = $"Se ha creado un perfil para el usuario {user_data.Nickname}"
                            };
                            PublishLogMessage(logData);

                            // Acknowledge the message
                            _channel.BasicAck(ea.DeliveryTag, false);
                        }
                        else
                        {
                            Console.WriteLine("Invalid data received. Message discarded.");
                            // Reject the message
                            _channel.BasicReject(ea.DeliveryTag, false);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error processing message: {ex.Message}");
                        // Reject the message
                        _channel.BasicReject(ea.DeliveryTag, false);
                    }
                };

                _channel.BasicConsume(queue: "register_queue", autoAck: false, consumer: consumer);

                Console.WriteLine(" [*] Waiting for logs.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error connecting to RabbitMQ: {ex.Message}");
                Console.WriteLine("Retrying in 5 seconds...");
                await Task.Delay(5000);
                await ConnectAndConsumeAsync();
            }
        }

        private async Task InsertUserProfileAsync(string userId, string nickname, string email)
        {
            try
            {
                Console.WriteLine("Inserting user profile into database...");

                // Open the connection if it's closed
                if (_dbConnection.State != ConnectionState.Open)
                {
                    await _dbConnection.OpenAsync();
                }

                using (var cmd = new NpgsqlCommand())
                {
                    cmd.Connection = _dbConnection;
                    cmd.CommandText = "INSERT INTO UserProfiles (UserId, Nickname, IsContactInfoPublic, MailingAddress) VALUES (@userId, @nickname, @isContactInfoPublic, @mailingAddress)";

                    cmd.Parameters.AddWithValue("userId", userId);
                    cmd.Parameters.AddWithValue("nickname", nickname);
                    cmd.Parameters.AddWithValue("isContactInfoPublic", false);
                    cmd.Parameters.AddWithValue("mailingAddress", email);

                    await cmd.ExecuteNonQueryAsync();
                }

                Console.WriteLine("User profile inserted successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error inserting user profile into database: {ex.Message}");
            }
        }

        private void PublishLogMessage(Log log)
        {
            try
            {
                using (var connection = _rabbitMqFactory.CreateConnection())
                using (var channel = connection.CreateModel())
                {
                    // Declara la cola de destino en RabbitMQ
                    channel.QueueDeclare(queue: "auth_log_queue", durable: false, exclusive: false, autoDelete: false, arguments: null);

                    // Serializa el log a JSON
                    var json = JsonConvert.SerializeObject(log);
                    var body = Encoding.UTF8.GetBytes(json);

                    // Publica el mensaje en la cola
                    channel.BasicPublish(exchange: "", routingKey: "auth_log_queue", basicProperties: null, body: body);
                }

                Console.WriteLine(" [x] Sent log message: {0}", log);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al enviar el mensaje de log: {ex.Message}");
            }
        }
    }
}
