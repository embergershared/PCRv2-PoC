using FunctionApp1.Models;
using Microsoft.EntityFrameworkCore;

namespace FunctionApp1.EfCore
{
    public class FuncApp1EfDbContext : DbContext
    {
        public FuncApp1EfDbContext(DbContextOptions<FuncApp1EfDbContext> options)
            : base(options)
        {
        }

        public DbSet<Student> Students { get; set; }
        public DbSet<Enrollment> Enrollments { get; set; }
        public DbSet<Course> Courses { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Course>().ToTable("Course");
            modelBuilder.Entity<Enrollment>().ToTable("Enrollment");
            modelBuilder.Entity<Student>().ToTable("Student");
        }
    }
}
