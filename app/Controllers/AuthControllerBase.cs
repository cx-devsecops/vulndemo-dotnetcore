using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Verademo.Data;
using Verademo.Models;

namespace Verademo.Controllers
{
    public abstract class AuthControllerBase : Controller
    {
        // PBKDF2 parameters: SHA-256, 100,000 iterations, 16-byte salt, 32-byte key
        private const int Pbkdf2Iterations = 100_000;
        private const int SaltSize = 16; // bytes
        private const int HashSize = 32; // bytes (SHA-256 output)
        private const char Separator = ':';

        protected BasicUser LoginUser(string userName, string passWord)
        {
            if (string.IsNullOrEmpty(userName))
            {
                return null;
            }

            using (var dbContext = new ApplicationDbContext())
            {
                // Retrieve the user record by username only; password verification is done in-memory
                // using the stored PBKDF2 hash (salt is embedded in the stored value).
                var found = dbContext.Database.SqlQuery<BasicUser>(
                    "select username, real_name as realname, blab_name as blabname, is_admin as isadmin, password from users where username=@username",
                    new System.Data.SqlClient.SqlParameter("@username", userName)).ToList();

                if (found.Count != 0 && VerifyPassword(passWord, found[0].Password))
                {
                    // Update last login timestamp
                    string userNameFromDB = found[0].UserName;
                    dbContext.Users.Where(u => u.UserName == userNameFromDB).First().LastLogin = DateTime.Now;
                    dbContext.SaveChanges();

                    HttpContext.Session.SetString("username", userName);
                    return found[0];
                }
            }

            return null;
        }

        protected string GetLoggedInUsername()
        {
            return HttpContext.Session.GetString("username");
        }

        protected void LogoutUser()
        {
            HttpContext.Session.SetString("username", "");
        }

        protected bool IsUserLoggedIn()
        {
            return string.IsNullOrEmpty(HttpContext.Session.GetString("username")) == false;
        }

        protected RedirectToRouteResult RedirectToLogin(string targetUrl)
        {
            return new RedirectToRouteResult(
                new RouteValueDictionary
                (new
                {
                    controller = "Account",
                    action = "Login",
                    ReturnUrl = HttpContext.Request.QueryString
                }));
        }

        /// <summary>
        /// Hashes a password using PBKDF2-HMAC-SHA256 with a randomly generated salt.
        /// The returned string has the format: iterations:base64(salt):base64(hash)
        /// </summary>
        protected static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }

            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                HashSize);

            return $"{Pbkdf2Iterations}{Separator}{Convert.ToBase64String(salt)}{Separator}{Convert.ToBase64String(hash)}";
        }

        /// <summary>
        /// Verifies a plaintext password against a stored PBKDF2 hash string.
        /// Uses constant-time comparison to prevent timing attacks.
        /// </summary>
        protected static bool VerifyPassword(string password, string storedHash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash))
            {
                return false;
            }

            var parts = storedHash.Split(Separator);
            if (parts.Length != 3)
            {
                return false;
            }

            if (!int.TryParse(parts[0], out int iterations) || iterations <= 0)
            {
                return false;
            }

            byte[] salt;
            byte[] expectedHash;
            try
            {
                salt = Convert.FromBase64String(parts[1]);
                expectedHash = Convert.FromBase64String(parts[2]);
            }
            catch (FormatException)
            {
                return false;
            }

            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expectedHash.Length);

            // Constant-time comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
    }
}