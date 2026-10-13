using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verademo.Commands
{
    public class AdminExecuteCommand
    {
        // Allowlist of permitted admin commands. Only these exact commands may be executed.
        private static readonly HashSet<string> AllowedActions = new HashSet<string>(StringComparer.Ordinal)
        {
            "status",
            "health",
            "version"
        };

        private string _action;
        public string Action
        {
            get { return _action; }
            set
            {
                _action = value;
                Exec();
            }
        }

        private void Exec()
        {
            // Validate _action against the allowlist before executing.
            // Passing user-controlled input directly to a shell (e.g., /bin/bash -c <input>)
            // enables command injection. Instead, only allow a fixed set of known safe commands
            // and invoke each one directly (UseShellExecute = false, no shell interpreter).
            if (!AllowedActions.Contains(_action))
            {
                throw new InvalidOperationException($"Action '{_action}' is not permitted.");
            }

            // Map the allowlisted action name to its concrete executable.
            // The executable path is hard-coded; no user input reaches FileName or Arguments.
            var processStartInfo = new ProcessStartInfo
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };

            switch (_action)
            {
                case "status":
                    processStartInfo.FileName = "/usr/bin/systemctl";
                    processStartInfo.ArgumentList.Add("status");
                    break;
                case "health":
                    processStartInfo.FileName = "/usr/bin/uptime";
                    break;
                case "version":
                    processStartInfo.FileName = "/usr/bin/uname";
                    processStartInfo.ArgumentList.Add("-r");
                    break;
                default:
                    // Should never reach here due to the allowlist check above.
                    throw new InvalidOperationException($"Action '{_action}' is not permitted.");
            }

            new Process { StartInfo = processStartInfo }.Start();
        }
    }
}