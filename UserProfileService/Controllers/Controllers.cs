using Microsoft.AspNetCore.Mvc;

using RabbitMQ.Client;
using System.Linq;
using System.Text;
using UserProfileService.Models;
using Newtonsoft.Json;
using Npgsql;
using System.Data;


namespace UserProfileService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserProfileController : ControllerBase
    {
        private readonly NpgsqlConnection _connection;
        private readonly ConnectionFactory _rabbitMqFactory;

        public UserProfileController(NpgsqlConnection connection, ConnectionFactory rabbitMqFactory)
        {
            _connection = connection;
            _rabbitMqFactory = rabbitMqFactory;
        }

        private void EnviarLogALaCola(Log log)
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
        }

        [HttpGet("{userId}")]
        public ActionResult<UserProfile> GetUserProfile(string userId)
        {
            try
            {
                // Realiza la consulta para obtener el perfil de usuario por ID
                var query = $"SELECT * FROM UserProfiles WHERE UserId = '{userId}'";
                using (var cmd = new NpgsqlCommand(query, _connection))
                {
                    // No necesitas abrir explícitamente la conexión aquí
                    using (var reader = cmd.ExecuteReader())
                    {
                        // Verifica si se encontró un perfil
                        if (reader.Read())
                        {
                            var userProfile = new UserProfile
                            {
                                UserId = reader.GetString(reader.GetOrdinal("UserId")),
                                Nickname = reader.GetString(reader.GetOrdinal("Nickname")),
                                PersonalPageUrl = reader.IsDBNull(reader.GetOrdinal("PersonalPageUrl")) ? null : reader.GetString(reader.GetOrdinal("PersonalPageUrl")),
                                IsContactInfoPublic = reader.GetBoolean(reader.GetOrdinal("IsContactInfoPublic")),
                                MailingAddress = reader.GetString(reader.GetOrdinal("MailingAddress")),
                                Biography = reader.IsDBNull(reader.GetOrdinal("Biography")) ? null : reader.GetString(reader.GetOrdinal("Biography")),
                                Organization = reader.IsDBNull(reader.GetOrdinal("Organization")) ? null : reader.GetString(reader.GetOrdinal("Organization")),
                                Country = reader.IsDBNull(reader.GetOrdinal("Country")) ? null : reader.GetString(reader.GetOrdinal("Country")),
                                SocialLinks = reader.IsDBNull(reader.GetOrdinal("SocialLinks")) ? null : ((string[])reader["SocialLinks"]).ToList()
                            };
                            return Ok(userProfile);
                        }
                        else
                        {
                            // Si no se encuentra el perfil, devuelve un NotFound
                            return NotFound();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Si hay un error, devuelve un StatusCode 500 y registra un log
                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Error", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Error al obtener perfil", Description = $"Error al obtener el perfil del usuario {userId}: {ex.Message}" });
                return StatusCode(500, $"Error al obtener el perfil del usuario {userId}");
            }
        }


        [HttpGet]
        public ActionResult<IEnumerable<UserProfile>> GetUserProfiles(int pageNumber = 1, int pageSize = 10)
        {
            try
            {
                // Calcula el índice del primer elemento de la página
                int skipIndex = (pageNumber - 1) * pageSize;

                // Realiza la consulta para obtener los perfiles de usuario con paginación
                var query = $"SELECT * FROM UserProfiles OFFSET {skipIndex} LIMIT {pageSize}";
                using (var cmd = new NpgsqlCommand(query, _connection))
                {
                    // No necesitas abrir explícitamente la conexión aquí
                    using (var reader = cmd.ExecuteReader())
                    {
                        // Lee los perfiles de usuario desde el resultado de la consulta
                        var userProfiles = new List<UserProfile>();
                        while (reader.Read())
                        {
                            var userProfile = new UserProfile
                            {
                                UserId = reader.GetString(reader.GetOrdinal("UserId")),
                                Nickname = reader.GetString(reader.GetOrdinal("Nickname")),
                                PersonalPageUrl = reader.IsDBNull(reader.GetOrdinal("PersonalPageUrl")) ? null : reader.GetString(reader.GetOrdinal("PersonalPageUrl")),
                                IsContactInfoPublic = reader.GetBoolean(reader.GetOrdinal("IsContactInfoPublic")),
                                MailingAddress = reader.GetString(reader.GetOrdinal("MailingAddress")),
                                Biography = reader.IsDBNull(reader.GetOrdinal("Biography")) ? null : reader.GetString(reader.GetOrdinal("Biography")),
                                Organization = reader.IsDBNull(reader.GetOrdinal("Organization")) ? null : reader.GetString(reader.GetOrdinal("Organization")),
                                Country = reader.IsDBNull(reader.GetOrdinal("Country")) ? null : reader.GetString(reader.GetOrdinal("Country")),
                                SocialLinks = reader.IsDBNull(reader.GetOrdinal("SocialLinks")) ? null : ((string[])reader["SocialLinks"]).ToList()
                            };
                            userProfiles.Add(userProfile);
                        }

                        // Devuelve los perfiles de usuario como una colección
                        return Ok(userProfiles);
                    }
                }
            }
            catch (Exception ex)
            {
                // Si hay un error, devuelve un StatusCode 500 y registra un log
                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Error", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Error al obtener perfiles", Description = $"Error al obtener los perfiles de usuario: {ex.Message}" });
                return StatusCode(500, $"Error al obtener los perfiles de usuario");
            }
        }


        [HttpGet("service/health")]
        public ActionResult<string> CheckServiceHealth()
        {
            try
            {
                // Abre y cierra la conexión a la base de datos para verificar si está disponible
                if (_connection.State != ConnectionState.Open)
                    {
                        return Ok("UP");
                    }else{
                        return StatusCode(500, "DOWN");
                    }
                
            }
            catch (Exception ex)
            {
                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Error", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Error al verificar salud del servicio", Description = $"Error al verificar la salud del servicio: {ex.Message}" });
                return StatusCode(500, "DOWN");
            }
        }

        [HttpPost]
        public ActionResult<UserProfile> CreateUserProfile(UserProfile userProfile)
        {
            try
            {
                // Realiza la inserción del nuevo perfil de usuario
                var query = $"INSERT INTO UserProfiles (UserId, Nickname, PersonalPageUrl, IsContactInfoPublic, MailingAddress, Biography, Organization, Country, SocialLinks) " +
                            $"VALUES ('{userProfile.UserId}', '{userProfile.Nickname}', '{userProfile.PersonalPageUrl ?? "NULL"}', " +
                            $"{userProfile.IsContactInfoPublic}, '{userProfile.MailingAddress}', '{userProfile.Biography ?? "NULL"}', " +
                            $"'{userProfile.Organization ?? "NULL"}', '{userProfile.Country ?? "NULL"}', " +
                            $"'{string.Join(",", userProfile.SocialLinks)}')";
                using (var cmd = new NpgsqlCommand(query, _connection))
                {
                    if (_connection.State != ConnectionState.Open)
                    {
                        _connection.Open();
                    }
                    cmd.ExecuteNonQuery();
                }

                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Info", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Perfil creado", Description = $"Se ha creado un perfil para el usuario {userProfile.UserId}" });
                return CreatedAtAction(nameof(GetUserProfile), new { userId = userProfile.UserId }, userProfile);
            }
            catch (Exception ex)
            {
                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Error", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Error al crear perfil", Description = $"Error al crear el perfil del usuario {userProfile.UserId}: {ex.Message}" });
                return StatusCode(500, $"Error al crear el perfil del usuario {userProfile.UserId}");
            }
        }

        [HttpPut("{userId}")]
        public IActionResult UpdateUserProfile(string userId, UserProfile userProfile)
        {
            Console.WriteLine($"Received UserProfile data for user {userId}:");
            Console.WriteLine($"UserId: {userProfile.UserId}");
            Console.WriteLine($"Nickname: {userProfile.Nickname}");
            Console.WriteLine($"PersonalPageUrl: {userProfile.PersonalPageUrl}");
            Console.WriteLine($"IsContactInfoPublic: {userProfile.IsContactInfoPublic}");
            Console.WriteLine($"MailingAddress: {userProfile.MailingAddress}");
            Console.WriteLine($"Biography: {userProfile.Biography}");
            Console.WriteLine($"Organization: {userProfile.Organization}");
            Console.WriteLine($"Country: {userProfile.Country}");
            Console.WriteLine($"SocialLinks: [{string.Join(",", userProfile.SocialLinks ?? new List<string>())}]");

            if (string.IsNullOrEmpty(userProfile.UserId) || string.IsNullOrEmpty(userProfile.Nickname) || string.IsNullOrEmpty(userProfile.MailingAddress))
            {
                return BadRequest("UserId, Nickname, and MailingAddress are required properties and cannot be null or empty.");
            }

            try
            {
                // Convertir lista de enlaces sociales a cadena
                var socialLinksString = userProfile.SocialLinks != null ? string.Join(",", userProfile.SocialLinks) : null;

                // Realizar la actualización del perfil de usuario
                var query = $"UPDATE UserProfiles SET " +
                                        $"Nickname = '{userProfile.Nickname}', " +
                                        $"PersonalPageUrl = '{userProfile.PersonalPageUrl ?? "NULL"}', " +
                                        $"IsContactInfoPublic = {userProfile.IsContactInfoPublic}, " +
                                        $"MailingAddress = '{userProfile.MailingAddress}', " +
                                        $"Biography = '{userProfile.Biography ?? "NULL"}', " +
                                        $"Organization = '{userProfile.Organization ?? "NULL"}', " +
                                        $"Country = '{userProfile.Country ?? "NULL"}', " +
                                        $"SocialLinks = ARRAY[{string.Join(",", userProfile.SocialLinks.Select(link => $"'{link}'"))}] " +
                                        $"WHERE UserId = '{userId}'";
                using (var cmd = new NpgsqlCommand(query, _connection))
                {
                    if (_connection.State != ConnectionState.Open)
                    {
                        _connection.Open();
                    }
                    cmd.ExecuteNonQuery();
                }

                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Info", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Perfil actualizado", Description = $"Se ha actualizado el perfil para el usuario {userId}" });
                return Ok();
            }
            catch (Exception ex)
            {
                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Error", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Error al actualizar perfil", Description = $"Error al actualizar el perfil del usuario {userId}: {ex.Message}" });
                return StatusCode(500, $"Error al actualizar el perfil del usuario {userId}");
            }
        }



        [HttpDelete("{userId}")]
        public IActionResult DeleteUserProfile(string userId)
        {
            try
            {
                // Realiza la eliminación del perfil de usuario
                var query = $"DELETE FROM UserProfiles WHERE UserId = '{userId}'";
                using (var cmd = new NpgsqlCommand(query, _connection))
                {
                    if (_connection.State != ConnectionState.Open)
                    {
                        _connection.Open();
                    }
                    cmd.ExecuteNonQuery();
                }

                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Info", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Perfil eliminado", Description = $"Se ha eliminado el perfil para el usuario {userId}" });
                return NoContent();
            }
            catch (Exception ex)
            {
                EnviarLogALaCola(new Log { Application = "UserProfileService", Type = "Error", Module = "UserProfile", Timestamp = DateTime.Now.ToString(), Summary = "Error al eliminar perfil", Description = $"Error al eliminar el perfil del usuario {userId}: {ex.Message}" });
                return StatusCode(500, $"Error al eliminar el perfil del usuario {userId}");
            }
        }

        // GET: api/Health
        [HttpGet("Health")]
        public ActionResult<object> CheckHealth()
        {
            var response = new
            {
                status = "UP",
                checks = new[]
                {
                    new
                    {
                        data = new
                        {
                            from = DateTime.UtcNow,
                            status = "READY"
                        },
                        name = "Readiness check",
                        status = "UP"
                    },
                    new
                    {
                        data = new
                        {
                            from = DateTime.UtcNow,
                            status = "ALIVE"
                        },
                        name = "Liveness check",
                        status = "UP"
                    }
                }
            };

            return Ok(response);
        }

    }

}
