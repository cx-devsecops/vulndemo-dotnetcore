using System;
using Microsoft.AspNetCore.Identity;
using Verademo.Models;
using Xunit;

namespace Verademo.Tests
{
    /// <summary>
    /// Tests for CWE-759 remediation: verifies that passwords are hashed using PBKDF2
    /// with a per-user random salt (via ASP.NET Core PasswordHasher) rather than
    /// unsalted MD5.
    /// </summary>
    public class UserPasswordHashingTests
    {
        // -------------------------------------------------------------------------
        // HashPassword — format and salt uniqueness
        // -------------------------------------------------------------------------

        [Fact]
        public void HashPassword_ReturnsNonEmptyHash()
        {
            // Hashing any plaintext password must produce a non-empty string.
            var user = new User { UserName = "testuser" };
            var hash = User.HashPassword(user, "MySecretPassword123");

            Assert.False(string.IsNullOrEmpty(hash));
        }

        [Fact]
        public void HashPassword_ProducesDifferentHashForSamePasswordEachCall()
        {
            // PBKDF2 generates a new random salt on every call, so two hashes of
            // identical plaintext must differ — this is the core CWE-759 fix.
            var user = new User { UserName = "testuser" };
            const string plainText = "SamePassword!";

            var hash1 = User.HashPassword(user, plainText);
            var hash2 = User.HashPassword(user, plainText);

            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void HashPassword_IsNotRawMd5()
        {
            // A raw unsalted MD5 of "password" is a known, fixed 32-hex-char string.
            // The PBKDF2 output must never equal that value.
            const string knownMd5OfPassword = "5f4dcc3b5aa765d61d8327deb882cf99";
            var user = new User { UserName = "testuser" };

            var hash = User.HashPassword(user, "password");

            Assert.NotEqual(knownMd5OfPassword, hash, StringComparer.OrdinalIgnoreCase);
        }

        [Fact]
        public void HashPassword_OutputIsNotRawInputString()
        {
            // The stored value must never be the plaintext password itself.
            var user = new User { UserName = "testuser" };
            const string plainText = "PlainTextPassword";

            var hash = User.HashPassword(user, plainText);

            Assert.NotEqual(plainText, hash);
        }

        [Fact]
        public void HashPassword_OutputLengthIndicatesPbkdf2Format()
        {
            // ASP.NET Core PasswordHasher v3 produces a Base64-encoded blob that is
            // significantly longer than a 32-character MD5 hex string.
            var user = new User { UserName = "testuser" };
            var hash = User.HashPassword(user, "AnyPassword");

            // PBKDF2/v3 output is at least 80 Base64 chars; MD5 hex is exactly 32.
            Assert.True(hash.Length > 32,
                $"Hash length {hash.Length} is too short to be a salted PBKDF2 hash.");
        }

        // -------------------------------------------------------------------------
        // VerifyPassword — correct and wrong passwords
        // -------------------------------------------------------------------------

        [Fact]
        public void VerifyPassword_SucceedsForCorrectPassword()
        {
            // A hash produced by HashPassword must verify successfully with the same
            // plaintext — the full round-trip must work.
            var user = new User { UserName = "testuser" };
            const string plainText = "CorrectHorseBatteryStaple";

            var hash = User.HashPassword(user, plainText);
            var result = User.VerifyPassword(user, hash, plainText);

            Assert.NotEqual(PasswordVerificationResult.Failed, result);
        }

        [Fact]
        public void VerifyPassword_FailsForWrongPassword()
        {
            // Providing an incorrect password must return Failed.
            var user = new User { UserName = "testuser" };
            var hash = User.HashPassword(user, "RealPassword");

            var result = User.VerifyPassword(user, hash, "WrongPassword");

            Assert.Equal(PasswordVerificationResult.Failed, result);
        }

        [Fact]
        public void VerifyPassword_FailsForEmptyPassword()
        {
            // An empty string must not verify against a hash of a real password.
            var user = new User { UserName = "testuser" };
            var hash = User.HashPassword(user, "RealPassword");

            var result = User.VerifyPassword(user, hash, "");

            Assert.Equal(PasswordVerificationResult.Failed, result);
        }

        [Fact]
        public void VerifyPassword_FailsForMd5HashOfSamePassword()
        {
            // If an attacker supplies the MD5 hex string of the password, verification
            // must still fail — PBKDF2 hashes are incompatible with MD5 digests.
            var user = new User { UserName = "testuser" };
            var hash = User.HashPassword(user, "password");
            const string md5OfPassword = "5f4dcc3b5aa765d61d8327deb882cf99";

            var result = User.VerifyPassword(user, hash, md5OfPassword);

            Assert.Equal(PasswordVerificationResult.Failed, result);
        }

        // -------------------------------------------------------------------------
        // User.Create — initial password seeding
        // -------------------------------------------------------------------------

        [Fact]
        public void UserCreate_PasswordIsNotPlainTextUsername()
        {
            // User.Create seeds the password from the username but must store a hash,
            // not the plaintext username itself.
            var user = User.Create("alice", "AliceB", "Alice Bloggs");

            Assert.NotEqual("alice", user.Password);
        }

        [Fact]
        public void UserCreate_PasswordIsNotMd5OfUsername()
        {
            // Known unsalted MD5("alice") = 6384e2b2184bcbf58eccf10ca7a6563c
            // The stored password must differ from that fixed string.
            const string md5OfAlice = "6384e2b2184bcbf58eccf10ca7a6563c";
            var user = User.Create("alice", "AliceB", "Alice Bloggs");

            Assert.NotEqual(md5OfAlice, user.Password, StringComparer.OrdinalIgnoreCase);
        }

        [Fact]
        public void UserCreate_TwoUsersWithSameUsernameHaveDifferentPasswordHashes()
        {
            // Each call to Create must generate a unique salt, so two users with the
            // same seed value must receive different stored hashes.
            var user1 = User.Create("alice", "AliceB", "Alice Bloggs");
            var user2 = User.Create("alice", "AliceB", "Alice Bloggs");

            Assert.NotEqual(user1.Password, user2.Password);
        }

        [Fact]
        public void UserCreate_StoredPasswordVerifiesWithOriginalInput()
        {
            // The password stored by Create must be verifiable using the username as
            // the original plaintext input (round-trip test).
            var user = User.Create("bob", "BobB", "Bob Builder");
            var result = User.VerifyPassword(user, user.Password, "bob");

            Assert.NotEqual(PasswordVerificationResult.Failed, result);
        }
    }
}
