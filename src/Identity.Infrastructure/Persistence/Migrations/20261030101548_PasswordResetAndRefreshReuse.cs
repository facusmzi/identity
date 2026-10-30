using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class PasswordResetAndRefreshReuse : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "password_reset_expires_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "password_reset_sent_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "password_reset_token_hash",
                table: "users",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "previous_refresh_token_hash",
                table: "sessions",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "refresh_rotated_at",
                table: "sessions",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "password_reset_expires_at",
                table: "users");

            migrationBuilder.DropColumn(
                name: "password_reset_sent_at",
                table: "users");

            migrationBuilder.DropColumn(
                name: "password_reset_token_hash",
                table: "users");

            migrationBuilder.DropColumn(
                name: "previous_refresh_token_hash",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "refresh_rotated_at",
                table: "sessions");
        }
    }
}
