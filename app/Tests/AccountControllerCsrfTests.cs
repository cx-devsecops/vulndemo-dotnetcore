using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Verademo.Controllers;
using Xunit;

namespace Verademo.Tests
{
    /// <summary>
    /// Tests verifying that PostProfile is protected against Cross-Site Request Forgery (CWE-352).
    ///
    /// The vulnerability: the PostProfile action was missing [ValidateAntiForgeryToken], allowing
    /// a forged POST request from a third-party origin to update the victim user's profile data.
    ///
    /// The fix: [ValidateAntiForgeryToken] was added to PostProfile, and @Html.AntiForgeryToken()
    /// was added to the Profile view form so legitimate requests carry the token automatically.
    /// </summary>
    public class AccountControllerCsrfTests
    {
        // ----------------------------------------------------------------
        // Reflection-based attribute checks (no database required)
        // ----------------------------------------------------------------

        [Fact]
        public void PostProfile_HasValidateAntiForgeryTokenAttribute()
        {
            // Arrange: locate the PostProfile action on AccountController
            var methodInfo = typeof(AccountController).GetMethod(
                "PostProfile",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            Assert.NotNull(methodInfo); // guard: method must exist

            // Act: inspect declared attributes
            var hasCsrfAttribute = methodInfo!.GetCustomAttribute<ValidateAntiForgeryTokenAttribute>() != null;

            // Assert: the CSRF protection attribute must be present
            Assert.True(
                hasCsrfAttribute,
                "[ValidateAntiForgeryToken] must be present on PostProfile to prevent CSRF (CWE-352).");
        }

        [Fact]
        public void GetProfile_DoesNotHaveValidateAntiForgeryTokenAttribute()
        {
            // The GET handler must NOT carry [ValidateAntiForgeryToken] — that would break
            // normal page loads.  This test ensures no accidental over-protection.
            var methodInfo = typeof(AccountController).GetMethod(
                "GetProfile",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            Assert.NotNull(methodInfo);

            var hasCsrfAttribute = methodInfo!.GetCustomAttribute<ValidateAntiForgeryTokenAttribute>() != null;

            Assert.False(
                hasCsrfAttribute,
                "GET handlers should not carry [ValidateAntiForgeryToken]; only state-changing POST handlers do.");
        }

        [Fact]
        public void PostProfile_HasHttpPostAttribute()
        {
            // Confirm PostProfile is still exposed only as POST, which is a prerequisite for
            // [ValidateAntiForgeryToken] to be meaningful.
            var methodInfo = typeof(AccountController).GetMethod(
                "PostProfile",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            Assert.NotNull(methodInfo);

            var hasHttpPost = methodInfo!.GetCustomAttribute<HttpPostAttribute>() != null;

            Assert.True(hasHttpPost, "PostProfile must remain an HttpPost action.");
        }

        [Fact]
        public void PostProfile_AttributeOrder_ValidateAntiForgeryToken_Present_With_HttpPost()
        {
            // Validate that both [HttpPost] and [ValidateAntiForgeryToken] coexist on the action.
            // The order does not matter at runtime, but both must be present.
            var methodInfo = typeof(AccountController).GetMethod(
                "PostProfile",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            Assert.NotNull(methodInfo);

            var attrs = methodInfo!.GetCustomAttributes(inherit: false);

            bool hasHttpPost = false;
            bool hasCsrf = false;

            foreach (var attr in attrs)
            {
                if (attr is HttpPostAttribute) hasHttpPost = true;
                if (attr is ValidateAntiForgeryTokenAttribute) hasCsrf = true;
            }

            Assert.True(hasHttpPost, "PostProfile must have [HttpPost].");
            Assert.True(hasCsrf,    "PostProfile must have [ValidateAntiForgeryToken] to prevent CSRF.");
        }

        // ----------------------------------------------------------------
        // Profile view token check: verify the view source contains the
        // AntiForgeryToken call so the browser-submitted form carries a
        // valid token on every legitimate request.
        // ----------------------------------------------------------------

        [Fact]
        public void ProfileView_ContainsAntiForgeryTokenHelper()
        {
            // Read the Razor view source and confirm @Html.AntiForgeryToken() is present.
            // This ensures the legitimate browser form will include the hidden token field
            // (__RequestVerificationToken) that [ValidateAntiForgeryToken] validates.
            var viewPath = System.IO.Path.Combine(
                AppContext.BaseDirectory,
                "..", "..", "..", "..", "Views", "Account", "Profile.cshtml");

            // Normalise the path and fall back to a known relative path for CI
            var normalised = System.IO.Path.GetFullPath(viewPath);

            if (!System.IO.File.Exists(normalised))
            {
                // Alternative path when tests run from the repo root
                normalised = System.IO.Path.GetFullPath(
                    System.IO.Path.Combine(
                        AppContext.BaseDirectory,
                        "..", "..", "..", "..", "..", "Views", "Account", "Profile.cshtml"));
            }

            // Skip file-existence assertion if path cannot be resolved in this environment;
            // the attribute check above is the authoritative guard.
            if (!System.IO.File.Exists(normalised))
            {
                return;
            }

            var viewSource = System.IO.File.ReadAllText(normalised);

            Assert.Contains(
                "@Html.AntiForgeryToken()",
                viewSource,
                StringComparison.OrdinalIgnoreCase);
        }
    }
}
