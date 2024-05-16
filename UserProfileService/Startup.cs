using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using RabbitMQ.Client;
using System;
using UserProfileService.Consumers;

namespace UserProfileService
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // Configuración de la conexión a la base de datos PostgreSQL
            services.AddSingleton<NpgsqlConnection>(_ =>
            {
                var connectionString = "Host=postgres;Port=5432;Database=reto2;Username=nomcci;Password=123";
                var connection = new NpgsqlConnection(connectionString);
                try
                {
                    connection.Open();
                    Console.WriteLine("Conexión a la base de datos establecida con éxito.");
                    using (var command = new NpgsqlCommand())
                    {
                        command.Connection = connection;
                        command.CommandText = @"
                            CREATE TABLE IF NOT EXISTS UserProfiles (
                                UserId VARCHAR(255) PRIMARY KEY,
                                Nickname VARCHAR(255) NOT NULL,
                                PersonalPageUrl VARCHAR(255),
                                IsContactInfoPublic BOOLEAN NOT NULL,
                                MailingAddress VARCHAR(255) NOT NULL,
                                Biography TEXT,
                                Organization VARCHAR(255),
                                Country VARCHAR(255),
                                SocialLinks TEXT[]
                            )
                        ";
                        command.ExecuteNonQuery();
                    }
                    return connection;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error al conectar con la base de datos: {ex.Message}");
                    // En caso de error al abrir la conexión, retornamos null
                    return null;
                }
            });

            // Configuración del controlador
            services.AddControllers();

            // Configuración de RabbitMQ
            services.AddScoped<RabbitMQConsumer>(); 

            // Configuración de la conexión RabbitMQ
            services.AddSingleton<ConnectionFactory>(sp =>
            {
                return new ConnectionFactory()
                {
                    HostName = Configuration["RabbitMQ:HostName"],
                    Port = int.Parse(Configuration["RabbitMQ:Port"]),
                    UserName = Configuration["RabbitMQ:UserName"],
                    Password = Configuration["RabbitMQ:Password"]
                };
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, RabbitMQConsumer rabbitMQConsumer)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });

            // Inicialización del consumidor RabbitMQ
            rabbitMQConsumer.StartConsuming();
        }
    }

    public static class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                    webBuilder.UseUrls($"http://userprofilemanager:{GetPortFromConfig()}");
                    Console.WriteLine($"API escuchando a http://localhost:{GetPortFromConfig()}");
                });

        private static string GetPortFromConfig()
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();

            return config["ServicePort"];
        }
    }
}
