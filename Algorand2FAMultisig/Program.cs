using Algorand2FAMultisig.Controllers;
using Algorand2FAMultisig.Extension;
using AlgorandAuthentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.OpenApi.Models;
using Prometheus;
using System.Reflection;

[assembly: AssemblyVersionAttribute("1.0.*")]

namespace Algorand2FAMultisig
{
    /// <summary>
    /// Main entry point
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Identifies specific run of the application
        /// </summary>
        public readonly static string InstanceId = Guid.NewGuid().ToString();
        /// <summary>
        /// Identifies specific run of the application
        /// </summary>
        public readonly static DateTimeOffset Started = DateTimeOffset.Now;
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

            var algorandAuthenticationOptions = new AlgorandAuthenticationOptions();
            builder.Configuration.GetSection("AlgorandAuthentication").Bind(algorandAuthenticationOptions);

            builder.Services
             .AddAuthentication(AlgorandAuthenticationHandler.ID)
             .AddAlgorand(o =>
             {
                 o.CheckExpiration = algorandAuthenticationOptions.CheckExpiration;
                 o.Debug = algorandAuthenticationOptions.Debug;
                 o.AlgodServer = algorandAuthenticationOptions.AlgodServer;
                 o.AlgodServerToken = algorandAuthenticationOptions.AlgodServerToken;
                 o.AlgodServerHeader = algorandAuthenticationOptions.AlgodServerHeader;
                 o.Realm = algorandAuthenticationOptions.Realm;
                 o.NetworkGenesisHash = algorandAuthenticationOptions.NetworkGenesisHash;
                 o.MsPerBlock = algorandAuthenticationOptions.MsPerBlock;
                 o.EmptySuccessOnFailure = algorandAuthenticationOptions.EmptySuccessOnFailure;
                 o.EmptySuccessOnFailure = algorandAuthenticationOptions.EmptySuccessOnFailure;
             });

            builder.Services.AddSingleton(typeof(Repository.Interface.IStorage), typeof(Repository.Implementation.Storage.StorageFile));
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
            builder.Services.AddOpenTelemetryExtension(builder.Configuration, DiagnosticsConfig.ServiceName);

            builder.Services.AddHealthChecks().AddCheck<HealthCheck>("twoFaServer");

            var app = builder.Build();

            app.Logger.LogInformation("Preloading singletons");
            _ = app.Services.GetService<Repository.Interface.IStorage>();
            _ = app.Services.GetService<Repository.Interface.IAuthenticatorApp>();
            var scopeFactory = app.Services.GetService<IServiceScopeFactory>();

            app.Logger.LogInformation("Preloading MultisigController");
            using (var scope = scopeFactory?.CreateScope())
            {
                _ = scope?.ServiceProvider.GetService<MultisigController>();
            }
            app.Logger.LogInformation("Preloading finished");


            // Configure the HTTP request pipeline.

            var version = Assembly.GetExecutingAssembly()?.GetName()?.Version;
            if (version != null)
            {
                Metrics.CreateGauge("BuildMajor", "version.Major").Set(Convert.ToDouble(version.Major));
                Metrics.CreateGauge("BuildMinor", "version.Minor").Set(Convert.ToDouble(version.Minor));
                Metrics.CreateGauge("BuildRevision", "version.Revision").Set(Convert.ToDouble(version.Revision));
                Metrics.CreateGauge("BuildBuild", "version.Build").Set(Convert.ToDouble(version.Build));
            }

            app.UseMetricServer();

            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseRouting();
            app.UseCors();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseHttpMetrics();
            app.MapControllers();
            app.MapMetrics();

            app.MapHealthChecks("/healthz", new HealthCheckOptions
            {
                ResultStatusCodes =
                    {
                        [HealthStatus.Healthy] = StatusCodes.Status200OK,
                        [HealthStatus.Degraded] = StatusCodes.Status200OK,
                        [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable
                    },
                ResponseWriter = HealthWriteResponse.WriteResponse
            });

            app.Run();
        }
    }
}