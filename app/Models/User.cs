using System;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Verademo.Models
{
    public class User
    {
        public string UserName { get; set; }
        [Column("blab_name")] public string BlabName { get; set; }
        [Column("real_name")] public string RealName { get; set; }
        [Column("password")] public string Password { get; set; }
        [Column("password_hint")] public string PasswordHint { get; set; }
        [Column("created_at")] public DateTime CreatedAt { get; set; }
        [Column("last_login")] public DateTime? LastLogin { get; set; }
        [Column("is_admin")] public bool IsAdmin { get; set; }

        // Framework-provided PBKDF2 hasher with a per-user random salt (CWE-759 fix).
        private static readonly PasswordHasher<User> _passwordHasher = new PasswordHasher<User>();

        public static User Create(string userName, string blabName, string realName, bool isAdmin = false)
        {
            // Use the userName as the initial password, hashed with a random salt via PBKDF2.
            var tempUser = new User { UserName = userName };
            var password = _passwordHasher.HashPassword(tempUser, userName);
            var createdAt = DateTime.Now;

            return new User(userName, password, createdAt, null, blabName, realName, isAdmin);
        }

        /// <summary>
        /// Hashes a plaintext password for the given user using PBKDF2 with a random salt.
        /// </summary>
        public static string HashPassword(User user, string plainTextPassword)
        {
            return _passwordHasher.HashPassword(user, plainTextPassword);
        }

        /// <summary>
        /// Verifies a plaintext password against the stored PBKDF2 hash.
        /// </summary>
        public static PasswordVerificationResult VerifyPassword(User user, string hashedPassword, string providedPassword)
        {
            return _passwordHasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }

        public User()
        {

        }

        public User(string userName, string password, DateTime createdAt, DateTime? lastLogin, string blabName, string realName, bool isAdmin)
        {
            UserName = userName;
            Password = password;
            PasswordHint = password;
            CreatedAt = createdAt;
            LastLogin = lastLogin;
            BlabName = blabName;
            RealName = realName;
            IsAdmin = isAdmin;
        }
    }
}