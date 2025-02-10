using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Pomelo.EntityFrameworkCore.MySql.Scaffolding.Internal;
using SecureBox.Models;

namespace SecureBox.Data;

public partial class AppDbContext : DbContext
{
    public AppDbContext()
    {
    }

    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<PasswordManage> PasswordManages { get; set; }

    public virtual DbSet<UserDetail> UserDetails { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see https://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseMySql("server=160.250.204.51;database=mramit_SecureBox;user=mramit_ecntech;password=Amit@2001;port=3306;persist security info=False;allow zero datetime=True;connect timeout=300", Microsoft.EntityFrameworkCore.ServerVersion.Parse("10.6.18-mariadb"));

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8mb3_general_ci")
            .HasCharSet("utf8mb3");

        modelBuilder.Entity<PasswordManage>(entity =>
        {
            entity.HasKey(e => e.Sno).HasName("PRIMARY");

            entity.ToTable("password_manage");

            entity.HasIndex(e => e.Sno, "Sno_UNIQUE").IsUnique();

            entity.Property(e => e.Sno).HasColumnType("int(11)");
            entity.Property(e => e.ApplicationName).HasMaxLength(128);
            entity.Property(e => e.ApplicationPassword).HasMaxLength(512);
            entity.Property(e => e.ApplicationUserId).HasMaxLength(45);
            entity.Property(e => e.UserId).HasColumnType("int(11)");
        });

        modelBuilder.Entity<UserDetail>(entity =>
        {
            entity.HasKey(e => e.Sno).HasName("PRIMARY");

            entity.ToTable("user_details");

            entity.HasIndex(e => e.Sno, "Sno_UNIQUE").IsUnique();

            entity.HasIndex(e => e.UserId, "UserId_UNIQUE").IsUnique();

            entity.HasIndex(e => e.UserMailId, "UserMailId_UNIQUE").IsUnique();

            entity.HasIndex(e => e.UserPhoneNo, "UserPhoneNo_UNIQUE").IsUnique();

            entity.Property(e => e.Sno).HasColumnType("int(11)");
            entity.Property(e => e.UserId).HasColumnType("int(11)");
            entity.Property(e => e.UserName).HasMaxLength(128);
            entity.Property(e => e.UserPassword).HasMaxLength(512);
            entity.Property(e => e.UserPhoneNo).HasColumnType("bigint(20)");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
