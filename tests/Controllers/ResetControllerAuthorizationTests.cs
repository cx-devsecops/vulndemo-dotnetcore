using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Session;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Moq;
using Verademo.Controllers;
using Verademo.Models;
using Xunit;

namespace Verademo.Tests.Controllers
{
    /// <summary>
    /// Tests for CWE-862 (Missing Authorization) remediation on ResetController.
    ///
    /// The vulnerability allowed any user (including unauthenticated ones) to POST to
    /// /Reset and trigger a full database schema reset.  The fix adds:
    ///   1. An authentication check (IsUserLoggedIn) — redirects to login if absent.
    ///   2. An admin-role check (IsUserAdmin) — returns 403 Forbidden if the authenticated
    ///      user is not an admin.
    ///
    /// These tests verify both guards are enforced on both GET and POST endpoints.
    /// They use a test-double subclass of ResetController that overrides the two
    /// protected helpers so no real database connection is required.
    /// </summary>

    // ---------------------------------------------------------------------------
    // Test-double: overrides IsUserLoggedIn / IsUserAdmin so tests can control
    // authorization state without a live database.
    // ---------------------------------------------------------------------------
    internal class TestableResetController : ResetController
    {
        private readonly bool _isLoggedIn;
        private readonly bool _isAdmin;

        public TestableResetController(bool isLoggedIn, bool isAdmin)
            : base(CreateFakeEnvironment())
        {
            _isLoggedIn = isLoggedIn;
            _isAdmin = isAdmin;

            // Wire up a real (in-memory) HTTP context with a session so the
            // base-class helpers that call HttpContext.Session do not throw.
            var httpContext = new DefaultHttpContext();
            httpContext.Session = BuildSession();
            ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };
        }

        // Override the two authorization helpers defined in AuthControllerBase.
        // This isolates these unit tests from the database entirely.
        new protected bool IsUserLoggedIn() => _isLoggedIn;
        new protected bool IsUserAdmin()    => _isAdmin;

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static Microsoft.AspNetCore.Hosting.IWebHostEnvironment CreateFakeEnvironment()
        {
            var mock = new Mock<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
            mock.SetupGet(e => e.ContentRootPath).Returns(string.Empty);
            mock.SetupGet(e => e.WebRootPath).Returns(string.Empty);
            mock.SetupGet(e => e.EnvironmentName).Returns("Testing");
            return mock.Object;
        }

        private static ISession BuildSession()
        {
            // DistributedSession requires a backing store — use MemoryDistributedCache.
            var opts = Options.Create(new MemoryDistributedCacheOptions());
            var cache = new MemoryDistributedCache(opts);
            var session = new DistributedSession(
                cache,
                sessionKey: System.Guid.NewGuid().ToString(),
                idleTimeout: System.TimeSpan.FromMinutes(20),
                ioTimeout: System.TimeSpan.FromSeconds(1),
                tryEstablishSession: () => true,
                loggerFactory: Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance,
                isNewSessionKey: true);
            return session;
        }
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    public class ResetControllerAuthorizationTests
    {
        // -----------------------------------------------------------------------
        // GET /Reset — unauthenticated
        // -----------------------------------------------------------------------

        [Fact]
        public void GetReset_UnauthenticatedUser_RedirectsToLogin()
        {
            // Arrange: user is NOT logged in
            var controller = new TestableResetController(isLoggedIn: false, isAdmin: false);

            // Act
            var result = controller.GetReset();

            // Assert: should be a redirect (to login), NOT a view
            Assert.IsAssignableFrom<RedirectToRouteResult>(result);
        }

        // -----------------------------------------------------------------------
        // GET /Reset — authenticated but not admin
        // -----------------------------------------------------------------------

        [Fact]
        public void GetReset_AuthenticatedNonAdminUser_ReturnsForbidden()
        {
            // Arrange: user IS logged in but is NOT an admin
            var controller = new TestableResetController(isLoggedIn: true, isAdmin: false);

            // Act
            var result = controller.GetReset();

            // Assert: must get a 403 Forbidden — not the reset view
            Assert.IsType<ForbidResult>(result);
        }

        // -----------------------------------------------------------------------
        // GET /Reset — authenticated admin
        // -----------------------------------------------------------------------

        [Fact]
        public void GetReset_AuthenticatedAdminUser_ReturnsResetView()
        {
            // Arrange: user IS logged in AND is an admin
            var controller = new TestableResetController(isLoggedIn: true, isAdmin: true);

            // Act
            var result = controller.GetReset();

            // Assert: admin should reach the reset view, not be redirected or forbidden
            Assert.IsType<ViewResult>(result);
        }

        // -----------------------------------------------------------------------
        // POST /Reset — unauthenticated
        // -----------------------------------------------------------------------

        [Fact]
        public void PostReset_UnauthenticatedUser_RedirectsToLogin()
        {
            // Arrange: user is NOT logged in
            var controller = new TestableResetController(isLoggedIn: false, isAdmin: false);

            // Act
            var result = controller.PostReset(confirm: "confirm", primary: null);

            // Assert: must redirect to login
            Assert.IsAssignableFrom<RedirectToRouteResult>(result);
        }

        // -----------------------------------------------------------------------
        // POST /Reset — authenticated but not admin
        // -----------------------------------------------------------------------

        [Fact]
        public void PostReset_AuthenticatedNonAdminUser_ReturnsForbidden()
        {
            // Arrange: user IS logged in but NOT an admin
            var controller = new TestableResetController(isLoggedIn: true, isAdmin: false);

            // Act — the confirm field has a value to rule out the "must confirm"
            // guard; the authorization guard must fire before that check.
            var result = controller.PostReset(confirm: "confirm", primary: null);

            // Assert: must get 403 Forbidden
            Assert.IsType<ForbidResult>(result);
        }

        // -----------------------------------------------------------------------
        // POST /Reset — authenticated admin but missing confirmation string
        // -----------------------------------------------------------------------

        [Fact]
        public void PostReset_AuthenticatedAdminUser_MissingConfirm_ReturnsViewWithError()
        {
            // Arrange: admin is logged in but does NOT supply the confirm parameter
            var controller = new TestableResetController(isLoggedIn: true, isAdmin: true);

            // Act: pass null/empty for confirm to exercise the confirm-required guard
            var result = controller.PostReset(confirm: null, primary: null);

            // Assert: should return a View with an error message (not forbidden, not redirect)
            var viewResult = Assert.IsType<ViewResult>(result);
            var model = Assert.IsType<ResetViewModel>(viewResult.Model);
            Assert.False(string.IsNullOrEmpty(model.Error));
        }

        // -----------------------------------------------------------------------
        // Security regression: ensure auth check happens BEFORE the confirm check
        // (so a non-admin cannot probe for any state-change side-effects by
        //  passing an empty confirm string).
        // -----------------------------------------------------------------------

        [Fact]
        public void PostReset_NonAdminUser_AuthCheckBeforeConfirmCheck_ReturnsForbiddenNotViewError()
        {
            // Arrange: non-admin, no confirm — authorization should fire first
            var controller = new TestableResetController(isLoggedIn: true, isAdmin: false);

            // Act
            var result = controller.PostReset(confirm: null, primary: null);

            // Assert: must be Forbidden, not a ViewResult with "You must confirm" error
            Assert.IsType<ForbidResult>(result);
            Assert.IsNotType<ViewResult>(result);
        }

        // -----------------------------------------------------------------------
        // Authorization state should be independent: logging in does NOT grant admin.
        // -----------------------------------------------------------------------

        [Fact]
        public void IsAuthorization_LoggedInWithoutAdminRole_IsInsufficient()
        {
            // Both GET and POST must reject a regular authenticated user.
            var controller = new TestableResetController(isLoggedIn: true, isAdmin: false);

            var getResult  = controller.GetReset();
            var postResult = controller.PostReset(confirm: "confirm", primary: null);

            Assert.IsType<ForbidResult>(getResult);
            Assert.IsType<ForbidResult>(postResult);
        }
    }
}
