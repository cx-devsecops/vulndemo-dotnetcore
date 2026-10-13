using System;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Verademo.Models;

namespace Verademo.Controllers
{
    public class ToolsController : AuthControllerBase
    {
        protected readonly log4net.ILog logger;

        // Allowlist pattern for valid hostname/IP characters only.
        // Accepts: letters, digits, hyphens, dots, colons (for IPv6), square brackets (for [::1]).
        // Explicitly rejects shell metacharacters (;, |, &, $, `, (, ), <, >, !, \, /, space, etc.).
        internal static readonly Regex ValidHostPattern =
            new Regex(@"^[a-zA-Z0-9\.\-\[\]:]{1,253}$", RegexOptions.Compiled);

        public ToolsController()
        {
            logger = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        }

        [HttpGet, ActionName("Tools")]
        public ActionResult GetTools()
        {
            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            return View(new ToolViewModel());
        }

        [HttpPost]
        public ActionResult Tools(string host, string fortuneFile)
        {
            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            var viewModel = new ToolViewModel();
            viewModel.Host = host;
            viewModel.PingResult = Ping(host);
            viewModel.FortuneResult = Fortune(fortuneFile);

            return View("Tools", viewModel);
        }

        private string Ping(string host)
        {
            if (string.IsNullOrEmpty(host))
            {
                return "";
            }

            // Validate host using an allowlist before passing as a discrete argument.
            // This prevents shell metacharacters from reaching the process invocation.
            if (!ValidHostPattern.IsMatch(host))
            {
                logger.Warn("Ping rejected invalid host input");
                return "Invalid host";
            }

            logger.Info("Pinging host");

            var output = new StringBuilder();
            try
            {
                // FIXED: invoke ping directly (no shell) passing host as a separate element
                // in the ArgumentList collection. With UseShellExecute=false and ArgumentList,
                // the OS passes each element as a discrete argv entry — no shell interpretation
                // occurs, so no shell metacharacter injection is possible.
                var proc = CreateArgListProcess("ping", new[] { "-c", "1", host });

                proc.ErrorDataReceived += delegate (object sender, DataReceivedEventArgs e) { output.AppendLine(e.Data); };
                proc.OutputDataReceived += delegate (object sender, DataReceivedEventArgs e) { output.AppendLine(e.Data); };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                proc.WaitForExit();
            }
            catch (Exception ex)
            {
                logger.Error(ex);
            }

            return output == null ? "" : output.ToString();
        }

        private string Fortune(string fortuneFile)
        {
            var output = new StringBuilder();

            if (string.IsNullOrEmpty(fortuneFile))
            {
                fortuneFile = "literature";
            }

            try
            {
                // START BAD CODE
                var fileName = "/bin/bash";
                var arguments = $"-c \"/bin/fortune {fortuneFile}\"";
                // END BAD CODE

                var proc = CreateStdOutProcess(fileName, arguments);

                proc.ErrorDataReceived += delegate (object sender, DataReceivedEventArgs e) { output.Append(e.Data); };
                proc.OutputDataReceived += delegate (object sender, DataReceivedEventArgs e) { output.Append(e.Data + "\n"); };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                proc.WaitForExit();
            }
            catch (Exception ex)
            {
                logger.Error(ex);
            }
            return output == null ? "" : output.ToString();
        }

        /// <summary>
        /// Creates a Process that invokes the given filename with each element of
        /// <paramref name="args"/> passed as a discrete argument (argv entry), bypassing
        /// shell interpretation entirely. UseShellExecute is false.
        /// </summary>
        private static Process CreateArgListProcess(string filename, string[] args)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = filename,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            // ArgumentList passes each string as a separate argv element without shell expansion.
            foreach (var arg in args)
            {
                startInfo.ArgumentList.Add(arg);
            }

            return new Process { StartInfo = startInfo };
        }

        private static Process CreateStdOutProcess(string filename, string arguments)
        {
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = filename,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            return proc;
        }
    }
}
