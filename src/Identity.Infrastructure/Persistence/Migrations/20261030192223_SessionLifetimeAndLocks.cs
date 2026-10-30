using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SessionLifetimeAndLocks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "locked_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "absolute_expires_at",
                table: "sessions",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "revoked_reason",
                table: "sessions",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            // Existing sessions get the same absolute limit new ones get (90 days from login) instead of the
            // column default above, which would expire all of them at once.
            migrationBuilder.Sql("UPDATE sessions SET absolute_expires_at = created_at + interval '90 days';");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "locked_at",
                table: "users");

            migrationBuilder.DropColumn(
                name: "absolute_expires_at",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "revoked_reason",
                table: "sessions");
        }
    }
}
