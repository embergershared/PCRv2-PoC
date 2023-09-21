using System;
using System.Threading.Tasks;
using FunctionApp1.EfCore;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using FunctionApp1.Helpers;

namespace FunctionApp1
{
    public class QueryDatabase
    {
        private readonly FuncApp1EfDbContext _efDbContext;

        public QueryDatabase(
            EfCore.FuncApp1EfDbContext efDbContext
            )
        {
            _efDbContext = efDbContext;
        }

        [FunctionName("QueryDatabase")]
        public async Task Run(
            [TimerTrigger("*/30 * * * * *")]TimerInfo myTimer, ILogger log)
        {
            log.LogInformation($"C# Timer triggered function \"QueryDatabase\" STARTED at: {DateTime.Now}");

            if (_efDbContext.Students != null)
            {
                var students = await _efDbContext.Students.ToListAsync();

                var studentWord = students.Count == 1 ? "student" : "students";
                Output.Log(log, $"Found {students.Count} {studentWord} in the DB:");

                foreach (var student in students)
                {
                    Output.Log(log, $"   {student.LastName} {student.FirstName},");
                }
            }

            log.LogInformation($"C# Timer triggered function \"QueryDatabase\" FINISHED at: {DateTime.Now}");
        }

    }
}
