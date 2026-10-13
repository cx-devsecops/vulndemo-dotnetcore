using System;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Verademo.Data;
using Verademo.Models;

namespace Verademo.Controllers
{
    public abstract class AuthControllerBase : Controller
    {
        protected BasicUser LoginUser(string userName, string passWord)
        {
            if (string.IsNullOrEmpty(userName))
            {
                return null;
            }

            using (var dbContext = new ApplicationDbContext())
            {
                // Fetch the user record first, then verify the password using PBKDF2
                // via PasswordHasher — avoids embedding password material in SQL and
                // eliminates the unsalted MD5 comparison (CWE-759 fix).
                var userRecord = dbContext.Users
                    .FirstOrDefault(u => u.UserName == userName);

                if (userRecord == null)
                {
                    return null;
                }

                var result = Verademo.Models.User.VerifyPassword(userRecord, userRecord.Password, passWord);

                if (result == PasswordVerificationResult.Failed)
                {
                    return null;
                }

                // Update last login timestamp
                userRecord.LastLogin = DateTime.Now;
                dbContext.SaveChanges();

                HttpContext.Session.SetString("username", userName);

                return new BasicUser
                {
                    UserName = userRecord.UserName,
                    RealName = userRecord.RealName,
                    BlabName = userRecord.BlabName,
                    IsAdmin = userRecord.IsAdmin
                };
            }
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

    }
}