using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

namespace UserProfileService.Models
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

          public DbSet<UserProfile> UserProfiles { get; set; }
    }
    public class UserProfile
    {
        public required string UserId { get; set; }
        public required string Nickname { get; set; }
        public string? PersonalPageUrl { get; set; }
        public bool IsContactInfoPublic { get; set; }
        public required string MailingAddress { get; set; }
        public string? Biography { get; set; }
        public string? Organization { get; set; }
        public string? Country { get; set; }
        public List<string>? SocialLinks { get; set; }
    }
  public class Log
    {
        [JsonProperty("application")]
        public string Application { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("module")]
        public string Module { get; set; }

        [JsonProperty("timestamp")]
        public string Timestamp { get; set; }

        [JsonProperty("summary")]
        public string Summary { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }
    }

    public class UserRegistrationLog
    {
        [JsonProperty("username")]
        public string Username { get; set; }
        
        [JsonProperty("email")]
        public string Email { get; set; }
        
        [JsonProperty("password")]
        public string Password { get; set; }
    }

}
