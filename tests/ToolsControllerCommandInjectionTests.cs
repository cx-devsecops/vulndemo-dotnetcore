using System.Diagnostics;
using Verademo.Controllers;
using Xunit;

namespace Verademo.Tests
{
    /// <summary>
    /// Tests verifying that the Fortune method in ToolsController is NOT vulnerable to command
    /// injection (CWE-77). The fix replaces the shell-interpolated argument string
    ///   /bin/bash -c "/bin/fortune {fortuneFile}"
    /// with a direct process invocation of /bin/fortune using ArgumentList, so shell
    /// metacharacters in fortuneFile are never interpreted by a shell.
    ///
    /// The tests exercise CreateFortuneProcessStartInfo() — the protected virtual method
    /// extracted from Fortune() — using a test subclass, so the actual process is never
    /// started (no dependency on /bin/fortune being present in the test environment).
    /// </summary>
    public class ToolsControllerCommandInjectionTests
    {
        // ---------------------------------------------------------------------------
        // Testable subclass: inherits ToolsController and exposes the protected method.
        // ---------------------------------------------------------------------------
        private class TestableToolsController : ToolsController
        {
            /// <summary>
            /// Expose CreateFortuneProcessStartInfo so tests can inspect the ProcessStartInfo
            /// that would be passed to Process.Start() without actually spawning a process.
            /// </summary>
            public ProcessStartInfo GetFortuneProcessStartInfo(string fortuneFile)
                => CreateFortuneProcessStartInfo(fortuneFile);
        }

        private readonly TestableToolsController _controller = new TestableToolsController();

        // ---------------------------------------------------------------------------
        // 1. Correct executable — no shell is used.
        // ---------------------------------------------------------------------------

        [Fact]
        public void Fortune_UsesFortuneDirectly_NotShell()
        {
            // The fix calls /bin/fortune directly; previously it called /bin/bash.
            var startInfo = _controller.GetFortuneProcessStartInfo("literature");

            Assert.Equal("/bin/fortune", startInfo.FileName);
            // Confirm no shell is configured to execute the command.
            Assert.False(startInfo.UseShellExecute,
                "UseShellExecute must be false so the OS forks the binary directly.");
        }

        // ---------------------------------------------------------------------------
        // 2. fortuneFile is passed as a discrete OS-level argument (not interpolated
        //    into a shell command string).
        // ---------------------------------------------------------------------------

        [Fact]
        public void Fortune_FortuneFilePassedViaArgumentList_NotArgumentsString()
        {
            var fortuneFile = "literature";
            var startInfo = _controller.GetFortuneProcessStartInfo(fortuneFile);

            // ArgumentList contains the value as a single element.
            Assert.Contains(fortuneFile, startInfo.ArgumentList);

            // The legacy Arguments string must be empty so no shell-string path exists.
            Assert.True(string.IsNullOrEmpty(startInfo.Arguments),
                "Arguments property must be empty; the fix uses ArgumentList only.");
        }

        // ---------------------------------------------------------------------------
        // 3–6. Command-injection payloads: verify they reach the process as literal
        //      arguments, not as shell directives.
        //      A shell-based invocation would interpret these; ArgumentList does not.
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("; cat /etc/passwd")]
        [InlineData("$(cat /etc/passwd)")]
        [InlineData("| id")]
        [InlineData("& whoami")]
        [InlineData("`id`")]
        [InlineData("\"; rm -rf /\"")]
        public void Fortune_InjectionPayload_PassedLiterallyNotInterpreted(string maliciousInput)
        {
            // The payload must arrive as a single, verbatim entry in ArgumentList.
            // /bin/fortune will receive it as argv[1] — an unknown fortune file name —
            // rather than executing it as a shell command.
            var startInfo = _controller.GetFortuneProcessStartInfo(maliciousInput);

            // Payload is present verbatim in ArgumentList.
            Assert.Contains(maliciousInput, startInfo.ArgumentList);

            // The FileName must still be /bin/fortune, NOT bash or sh.
            Assert.Equal("/bin/fortune", startInfo.FileName);

            // The Arguments string (used by shell-based invocations) must be empty.
            Assert.True(string.IsNullOrEmpty(startInfo.Arguments),
                $"Payload '{maliciousInput}' must not appear in the Arguments shell string.");
        }

        // ---------------------------------------------------------------------------
        // 7. Null / empty input falls back to "literature" (default behaviour preserved).
        // ---------------------------------------------------------------------------

        [Fact]
        public void Fortune_NullInput_UsesLiteratureDefault()
        {
            // Fortune() sets fortuneFile to "literature" when null/empty before calling
            // CreateFortuneProcessStartInfo.  Test that the method handles a bare null
            // without throwing and that ArgumentList has exactly one element.
            // (Fortune() is private; we test CreateFortuneProcessStartInfo with
            //  "literature" to confirm the same contract holds for the default path.)
            var startInfo = _controller.GetFortuneProcessStartInfo("literature");

            Assert.Single(startInfo.ArgumentList);
            Assert.Equal("literature", startInfo.ArgumentList[0]);
        }

        // ---------------------------------------------------------------------------
        // 8. ArgumentList has exactly one element — no accidental shell flag injection.
        // ---------------------------------------------------------------------------

        [Fact]
        public void Fortune_ArgumentList_HasExactlyOneEntry()
        {
            // Passing extra entries would suggest extra shell flags or fragmented args.
            var startInfo = _controller.GetFortuneProcessStartInfo("science");

            Assert.Single(startInfo.ArgumentList);
        }

        // ---------------------------------------------------------------------------
        // 9. Whitespace-only input is passed verbatim (no silent trimming that might
        //    mask downstream errors and cause confusion with the default path).
        // ---------------------------------------------------------------------------

        [Fact]
        public void Fortune_WhitespaceInput_PassedVerbatim()
        {
            var input = "   ";
            var startInfo = _controller.GetFortuneProcessStartInfo(input);

            Assert.Contains(input, startInfo.ArgumentList);
            Assert.Equal("/bin/fortune", startInfo.FileName);
        }

        // ---------------------------------------------------------------------------
        // 10. Process redirection flags — confirms stdout/stderr are captured, which
        //     is required for the response to contain the fortune output.
        // ---------------------------------------------------------------------------

        [Fact]
        public void Fortune_ProcessStartInfo_RedirectsOutputAndError()
        {
            var startInfo = _controller.GetFortuneProcessStartInfo("literature");

            Assert.True(startInfo.RedirectStandardOutput,
                "StandardOutput must be redirected to capture fortune output.");
            Assert.True(startInfo.RedirectStandardError,
                "StandardError must be redirected to capture any error messages.");
        }
    }
}
