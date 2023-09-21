using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using FunctionApp1.Helpers;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using WinSCP;

namespace FunctionApp1
{
    public class SftpClient
    {
        [FunctionName("SftpClient")]
        public void Run([TimerTrigger("0 */1 * * * *")] TimerInfo myTimer, ILogger log, ExecutionContext context)
        {
            Output.Log(log, $"C# Timer triggered function \"SftpClient\" STARTED at: {DateTime.Now}");


            // Grabbing SFTP Connection settings
            var sftpHostName = Environment.GetEnvironmentVariable("SftpHost") ??
                             throw new InvalidOperationException(
                                 "Environment Variable 'SftpHost' not found.");
            var sftpUser = Environment.GetEnvironmentVariable("SftpUser") ??
                               throw new InvalidOperationException(
                                   "Environment Variable 'SftpUser' not found.");
            var sftpPwd = Environment.GetEnvironmentVariable("SftpPwd") ??
                               throw new InvalidOperationException(
                                   "Environment Variable 'SftpPwd' not found.");
            var sftpHomeDir = Environment.GetEnvironmentVariable("SftpHomeDir") ??
                          throw new InvalidOperationException(
                              "Environment Variable 'SftpHomeDir' not found.");

            try
            {
                // Setup session options
                var sessionOptions = new SessionOptions
                {
                    Protocol = Protocol.Sftp,
                    HostName = sftpHostName,
                    UserName = sftpUser,
                    Password = sftpPwd,
                    SshHostKeyPolicy = SshHostKeyPolicy.GiveUpSecurityAndAcceptAny
                    //SshHostKeyFingerprint = "ssh-rsa 2048 xxxxxxxxxxx..."
                };
                using var session = new Session
                {
                    ExecutablePath = Path.Combine(context.FunctionAppDirectory, "winscp.exe")
                };

                // Connect
                session.Open(sessionOptions);

                // List Home Directory content
                var directory = session.ListDirectory(sftpHomeDir);

                foreach (var fileInfo in directory.Files.Cast<RemoteFileInfo>())
                {
                    Output.Log(log, $"{fileInfo.Name} with size {fileInfo.Length}, permissions {fileInfo.FilePermissions} and last modification at {fileInfo.LastWriteTime}");
                }
            }
            catch (Exception e)
            {
                log.LogError($"Error: {e}");
                Output.Log(log, $"Error: {e}");
            }

            Output.Log(log, $"C# Timer triggered function \"SftpClient\" FINISHED at: {DateTime.Now}");
        }
    }
}
