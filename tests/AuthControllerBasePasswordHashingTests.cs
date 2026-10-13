using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Xunit;

// ---------------------------------------------------------------------------
// Tests for the password-hashing fix in AuthControllerBase (CWE-759).
//
// The vulnerable code used unsalted MD5 to store passwords.
// The fix replaced it with PBKDF2-HMAC-SHA256 (Rfc2898DeriveBytes) plus a
// cryptographically random salt, and uses CryptographicOperations.FixedTimeEquals
// for constant-time verification.
//
// Because HashPassword and VerifyPassword are protected static members we
// expose them through a minimal concrete subclass defined at the bottom of
// this file.
// ---------------------------------------------------------------------------

namespace Verademo.Tests
{
    public class AuthControllerBasePasswordHashingTests
    {
        // ----------------------------------------------------------------
        // Helper: concrete subclass that exposes the protected static methods
        // ----------------------------------------------------------------
        private sealed class TestableAuth : Verademo.Controllers.AuthControllerBase
        {
            public static string CallHashPassword(string password)
                => HashPassword(password);

            public static bool CallVerifyPassword(string password, string storedHash)
                => VerifyPassword(password, storedHash);
        }

        // ================================================================
        // 1. Basic round-trip: HashPassword + VerifyPassword
        // ================================================================

        [Theory]
        [InlineData("correct-horse-battery-staple")]
        [InlineData("P@$$w0rd!")]
        [InlineData("a")]                          // minimal length
        [InlineData("unicode-é-中文")] // non-ASCII characters
        public void HashAndVerify_CorrectPassword_ReturnsTrue(string password)
        {
            var stored = TestableAuth.CallHashPassword(password);
            Assert.True(TestableAuth.CallVerifyPassword(password, stored),
                $"VerifyPassword should return true for the original password '{password}'.");
        }

        [Theory]
        [InlineData("correct-horse-battery-staple", "wrong-password")]
        [InlineData("secret123", "secret124")]
        [InlineData("admin", "ADMIN")]            // case-sensitive check
        [InlineData("password", "password ")]     // trailing space
        public void HashAndVerify_WrongPassword_ReturnsFalse(string original, string attempt)
        {
            var stored = TestableAuth.CallHashPassword(original);
            Assert.False(TestableAuth.CallVerifyPassword(attempt, stored),
                $"VerifyPassword should reject '{attempt}' when stored hash is for '{original}'.");
        }

        // ================================================================
        // 2. Salt uniqueness: same password must produce different stored hashes
        // ================================================================

        [Fact]
        public void HashPassword_SamePassword_ProducesDistinctHashes()
        {
            const string password = "samepassword";
            var hash1 = TestableAuth.CallHashPassword(password);
            var hash2 = TestableAuth.CallHashPassword(password);

            Assert.NotEqual(hash1, hash2,
                "Two calls to HashPassword with the same password must yield different hashes " +
                "(each call generates a fresh random salt — CWE-759 regression guard).");
        }

        [Fact]
        public void HashPassword_MultiplePasswords_AllHaveDifferentSalts()
        {
            var passwords = new[] { "alpha", "beta", "gamma", "delta" };
            var salts = new List<string>();

            foreach (var pw in passwords)
            {
                // Extract the salt segment (format: iterations:base64salt:base64hash)
                var parts = TestableAuth.CallHashPassword(pw).Split(':');
                Assert.Equal(3, parts.Length);
                salts.Add(parts[1]);
            }

            // Every salt must be unique
            Assert.Equal(salts.Count, new HashSet<string>(salts).Count);
        }

        // ================================================================
        // 3. Format / storage contract
        // ================================================================

        [Fact]
        public void HashPassword_OutputFormat_IsIterationsSaltHash()
        {
            var stored = TestableAuth.CallHashPassword("test");

            // Must be exactly "iterations:base64salt:base64hash"
            var parts = stored.Split(':');
            Assert.Equal(3, parts.Length);

            // First segment is the iteration count (positive integer)
            Assert.True(int.TryParse(parts[0], out int iterations));
            Assert.True(iterations > 0);

            // Second and third segments must be valid Base64
            Assert.True(IsBase64(parts[1]), "Salt segment must be valid Base64.");
            Assert.True(IsBase64(parts[2]), "Hash segment must be valid Base64.");
        }

        [Fact]
        public void HashPassword_SaltLength_Is16Bytes()
        {
            var stored = TestableAuth.CallHashPassword("test");
            var parts = stored.Split(':');
            var salt = Convert.FromBase64String(parts[1]);
            Assert.Equal(16, salt.Length);
        }

        [Fact]
        public void HashPassword_HashLength_Is32Bytes()
        {
            var stored = TestableAuth.CallHashPassword("test");
            var parts = stored.Split(':');
            var hash = Convert.FromBase64String(parts[2]);
            Assert.Equal(32, hash.Length);
        }

        // ================================================================
        // 4. Security property: output MUST NOT be a raw MD5 hex string
        //    (ensures the old unsalted MD5 code is no longer used)
        // ================================================================

        [Theory]
        [InlineData("password")]
        [InlineData("admin")]
        [InlineData("john")]
        public void HashPassword_OutputIsNotMd5Hex(string password)
        {
            var stored = TestableAuth.CallHashPassword(password);

            // MD5 hex strings are exactly 32 lowercase hex characters.
            // The new output must NOT match that pattern.
            bool looksMd5 = stored.Length == 32 && IsHexString(stored);
            Assert.False(looksMd5,
                $"HashPassword(\"{password}\") returned what looks like an unsalted MD5 hex string. " +
                "The CWE-759 vulnerability (one-way hash without salt) may still be present.");
        }

        [Theory]
        [InlineData("password",   "5f4dcc3b5aa765d61d8327deb882cf99")] // MD5("password")
        [InlineData("admin",      "21232f297a57a5a743894a0e4a801fc3")] // MD5("admin")
        [InlineData("john",       "527bd5b5d689e2c32ae974c6229ff785")] // MD5("john")
        public void HashPassword_OutputDoesNotMatchKnownMd5(string password, string md5Hex)
        {
            var stored = TestableAuth.CallHashPassword(password);
            Assert.NotEqual(md5Hex, stored,
                $"HashPassword(\"{password}\") must not return the unsalted MD5 value '{md5Hex}'.");
        }

        // ================================================================
        // 5. Security property: known MD5 hex strings must NOT verify
        //    (protect against stored legacy MD5 hashes being accepted)
        // ================================================================

        [Theory]
        [InlineData("password",   "5f4dcc3b5aa765d61d8327deb882cf99")]
        [InlineData("admin",      "21232f297a57a5a743894a0e4a801fc3")]
        public void VerifyPassword_RejectedForLegacyMd5Hash(string password, string md5Hex)
        {
            Assert.False(TestableAuth.CallVerifyPassword(password, md5Hex),
                $"VerifyPassword must reject the legacy unsalted MD5 hash for '{password}'.");
        }

        // ================================================================
        // 6. Edge / null / empty inputs
        // ================================================================

        [Fact]
        public void HashPassword_EmptyInput_ReturnsEmpty()
        {
            Assert.Equal(string.Empty, TestableAuth.CallHashPassword(string.Empty));
        }

        [Fact]
        public void HashPassword_NullInput_ReturnsEmpty()
        {
            Assert.Equal(string.Empty, TestableAuth.CallHashPassword(null!));
        }

        [Theory]
        [InlineData(null,   "validhash")]
        [InlineData("",     "validhash")]
        [InlineData("pass", null)]
        [InlineData("pass", "")]
        public void VerifyPassword_NullOrEmptyInputs_ReturnsFalse(string? password, string? storedHash)
        {
            Assert.False(TestableAuth.CallVerifyPassword(password!, storedHash!));
        }

        [Theory]
        [InlineData("notbase64atall")]         // only 1 segment
        [InlineData("100000:onlytwo")]         // only 2 segments
        [InlineData("notanint:abc:def")]       // non-integer iterations
        [InlineData("-1:abc:def")]             // negative iterations
        [InlineData("0:abc:def")]              // zero iterations
        [InlineData("100000:!!!:!!!")]         // invalid Base64 for salt/hash
        public void VerifyPassword_MalformedStoredHash_ReturnsFalse(string malformed)
        {
            Assert.False(TestableAuth.CallVerifyPassword("anypassword", malformed),
                $"VerifyPassword must gracefully return false for malformed hash: '{malformed}'.");
        }

        // ================================================================
        // 7. Timing-safe comparison: different length hashes must not throw
        // ================================================================

        [Fact]
        public void VerifyPassword_StoredHashWithDifferentHashLength_ReturnsFalse()
        {
            // Craft a stored hash whose hash segment is a different length than expected.
            // FixedTimeEquals requires equal lengths; VerifyPassword derives the length
            // from the stored hash so this must not throw.
            var stored = TestableAuth.CallHashPassword("mypassword");
            var parts = stored.Split(':');
            // Append a byte to the hash to change its decoded length
            var longerHash = Convert.ToBase64String(
                new byte[Convert.FromBase64String(parts[2]).Length + 1]);
            var tampered = $"{parts[0]}:{parts[1]}:{longerHash}";

            // Must not throw and must return false
            var result = Record.Exception(
                () => TestableAuth.CallVerifyPassword("mypassword", tampered));
            Assert.Null(result); // No exception
            Assert.False(TestableAuth.CallVerifyPassword("mypassword", tampered));
        }

        // ================================================================
        // 8. High iteration count: PBKDF2 must use a work factor ≥ 10,000
        //    (NIST SP 800-132 minimum for password hashing)
        // ================================================================

        [Fact]
        public void HashPassword_IterationCount_MeetsMinimumWorkFactor()
        {
            var stored = TestableAuth.CallHashPassword("test");
            var parts = stored.Split(':');
            int.TryParse(parts[0], out int iterations);
            Assert.True(iterations >= 10_000,
                $"PBKDF2 iteration count must be at least 10,000 (got {iterations}). " +
                "Low iteration counts make offline brute-force attacks practical.");
        }

        // ================================================================
        // Private helpers
        // ================================================================

        private static bool IsBase64(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            try { Convert.FromBase64String(s); return true; }
            catch { return false; }
        }

        private static bool IsHexString(string s)
        {
            foreach (char c in s)
                if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F'))
                    return false;
            return true;
        }
    }
}
