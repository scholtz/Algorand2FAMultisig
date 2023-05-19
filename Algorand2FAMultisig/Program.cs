using AlgorandAuthentication;
using Microsoft.OpenApi.Models;

namespace Algorand2FAMultisig
{
    /// <summary>
    /// Main entry point
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Main entry point
        /// </summary>
        /// <param name="args"></param>
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Algorand 2FA Service API",
                    Version = "v1",
                    Description = File.ReadAllText("doc/doc.md")
                });
                c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First()); //This line

                c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
                {
                    Description = "SigTx",
                    In = ParameterLocation.Header,
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
                c.OperationFilter<Swashbuckle.AspNetCore.Filters.SecurityRequirementsOperationFilter>();

                c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, $"doc/doc.xml"));
            });

            builder.Services
             .AddAuthentication(AlgorandAuthenticationHandler.ID)
             .AddAlgorand(o =>
             {
                 o.CheckExpiration = true;
                 o.AlgodServer = builder.Configuration["algod:server"];
                 o.AlgodServerToken = builder.Configuration["algod:token"];
                 o.AlgodServerHeader = builder.Configuration["algod:header"];
                 o.Realm = builder.Configuration["algod:realm"];
                 o.NetworkGenesisHash = builder.Configuration["algod:networkGenesisHash"];
             });

            builder.Services.AddSingleton(typeof(Repository.Interface.IAuthenticatorApp), typeof(Repository.Implementation.GoogleAuthenticatorApp));
            builder.Services.AddProblemDetails();

            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(
                policy =>
                {
                    policy.SetIsOriginAllowed(origin => true);
                    policy.AllowAnyHeader();
                    policy.AllowAnyMethod();
                    policy.AllowCredentials();
                });
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseCors();
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}