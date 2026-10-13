using System;
using Verademo.Models;
using Xunit;

namespace Verademo.Tests.Models
{
    /// <summary>
    /// Tests for CWE-522 remediation: the User model must NOT store
    /// the password (or its hash) as the PasswordHint.
    /// </summary>
    public class UserTests
    {
        // ---------------------------------------------------------------
        // Constructor tests: PasswordHint must never equal Password
        // ---------------------------------------------------------------

        [Fact]
        public void Constructor_PasswordHint_IsNotSetToPassword()
        {
            // Arrange
            var password = "s3cr3tP@ssw0rd!";

            // Act
            var user = new User(
                userName: "testuser",
                password: password,
                createdAt: DateTime.UtcNow,
                lastLogin: null,
                blabName: "TestBlab",
                realName: "Test User",
                isAdmin: false);

            // Assert: PasswordHint must NOT contain or equal the password value
            Assert.NotEqual(password, user.PasswordHint);
        }

        [Fact]
        public void Constructor_PasswordHint_IsNullByDefault()
        {
            // When creating a User via the constructor the hint should be
            // null unless explicitly provided; storing the password as the
            // hint is the CWE-522 vulnerability.
            var user = new User(
                userName: "alice",
                password: "aHashedOrRawPassword",
                createdAt: DateTime.UtcNow,
                lastLogin: null,
                blabName: "AlicesBlab",
                realName: "Alice",
                isAdmin: false);

            Assert.Null(user.PasswordHint);
        }

        [Fact]
        public void Constructor_Password_IsStoredCorrectly()
        {
            // The Password property itself must still be set (functionality preserved).
            var password = "myPassword123";

            var user = new User(
                userName: "bob",
                password: password,
                createdAt: DateTime.UtcNow,
                lastLogin: null,
                blabName: "BobsBlab",
                realName: "Bob",
                isAdmin: false);

            Assert.Equal(password, user.Password);
        }

        [Fact]
        public void Constructor_OtherProperties_AreSetCorrectly()
        {
            // Verify the rest of the constructor is unaffected by the fix.
            var now = DateTime.UtcNow;
            var lastLogin = now.AddDays(-1);

            var user = new User(
                userName: "carol",
                password: "pass",
                createdAt: now,
                lastLogin: lastLogin,
                blabName: "CarolsBlab",
                realName: "Carol Smith",
                isAdmin: true);

            Assert.Equal("carol", user.UserName);
            Assert.Equal(now, user.CreatedAt);
            Assert.Equal(lastLogin, user.LastLogin);
            Assert.Equal("CarolsBlab", user.BlabName);
            Assert.Equal("Carol Smith", user.RealName);
            Assert.True(user.IsAdmin);
        }

        // ---------------------------------------------------------------
        // Create factory tests: PasswordHint must not contain password
        // ---------------------------------------------------------------

        [Fact]
        public void Create_PasswordHint_IsNotSetToPassword()
        {
            // User.Create generates an MD5 hash as the password; the hint
            // must still not hold that hash value.
            var user = User.Create(
                userName: "dave",
                blabName: "DavesBlab",
                realName: "Dave");

            // PasswordHint must not be equal to the generated password hash
            Assert.NotEqual(user.Password, user.PasswordHint);
        }

        [Fact]
        public void Create_PasswordHint_IsNull()
        {
            var user = User.Create(
                userName: "eve",
                blabName: "EvesBlab",
                realName: "Eve");

            Assert.Null(user.PasswordHint);
        }

        [Fact]
        public void Create_Password_IsNotNullOrEmpty()
        {
            // Verify the factory still sets a password even after the fix.
            var user = User.Create(
                userName: "frank",
                blabName: "FranksBlab",
                realName: "Frank");

            Assert.False(string.IsNullOrEmpty(user.Password),
                "User.Create should still generate a non-empty password hash.");
        }

        // ---------------------------------------------------------------
        // Default constructor test
        // ---------------------------------------------------------------

        [Fact]
        public void DefaultConstructor_PasswordHint_IsNull()
        {
            // The parameterless constructor (used by ORM hydration) must also
            // leave PasswordHint as null rather than pre-filling it.
            var user = new User();

            Assert.Null(user.PasswordHint);
        }

        // ---------------------------------------------------------------
        // Regression: PasswordHint can be explicitly set to a custom value
        // ---------------------------------------------------------------

        [Fact]
        public void PasswordHint_CanBeSetToAMeaningfulHint()
        {
            // Ensure the property setter still works for legitimate hints.
            var user = new User(
                userName: "grace",
                password: "actualPassword",
                createdAt: DateTime.UtcNow,
                lastLogin: null,
                blabName: "GracesBlab",
                realName: "Grace",
                isAdmin: false);

            // Simulate a user explicitly providing a text hint (not the password).
            user.PasswordHint = "My dog's name";

            Assert.Equal("My dog's name", user.PasswordHint);
            Assert.NotEqual("actualPassword", user.PasswordHint);
        }
    }
}
