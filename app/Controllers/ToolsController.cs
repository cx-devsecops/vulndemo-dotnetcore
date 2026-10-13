using System;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Verademo.Models;

namespace Verademo.Controllers
{
    public class ToolsController : AuthControllerBase
    {
        protected readonly log4net.ILog logger;

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

            logger.Info("Pinging: " + host);

            var output = new StringBuilder();
            try
            {
                // START BAD CODE
                var fileName = "bash";
                var arguments = "-c \"ping -c1 " + host + "\"";
                // END BAD CODE

                var proc = CreateStdOutProcess(fileName, arguments);

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
                // Invoke /bin/fortune directly without a shell, passing fortuneFile as a
                // discrete argument via ArgumentList. This eliminates the shell injection
                // vector: no shell is spawned, so metacharacters in fortuneFile have no effect.
                var startInfo = CreateFortuneProcessStartInfo(fortuneFile);
                var proc = new Process { StartInfo = startInfo };

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
        /// Creates the ProcessStartInfo for the fortune command. Protected virtual to allow
        /// testing of argument construction without actually spawning a process.
        /// </summary>
        protected virtual ProcessStartInfo CreateFortuneProcessStartInfo(string fortuneFile)
        {
            // Directly invoke /bin/fortune — no shell (UseShellExecute=false, FileName is the
            // binary itself). ArgumentList adds fortuneFile as a discrete OS-level argument,
            // so shell metacharacters (;, |, &, $, etc.) in fortuneFile are never interpreted.
            var startInfo = new ProcessStartInfo
            {
                FileName = "/bin/fortune",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add(fortuneFile);
            return startInfo;
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