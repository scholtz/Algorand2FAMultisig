using Microsoft.Extensions.DependencyInjection;
using System;
using Microsoft.Extensions.Configuration;
using OpenTelemetry.Trace;
using OpenTelemetry.Resources;
using OpenTelemetry.Instrumentation.AspNetCore;
using OpenTelemetry.Exporter;

namespace Algorand2FAMultisig.Extension
{
    /// <summary>
    /// Extensions to allow telemetry tracking
    /// </summary>
    public static class TelemetryExtensions
    {
        /// <summary>
        /// Adds telemetry if configured in appsettings
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <param name="serviceName"></param>
        /// <returns></returns>
        public static IServiceCollection AddOpenTelemetryExtension(this IServiceCollection services, IConfiguration configuration, string serviceName)
        {
            // Note: Switch between Zipkin/Jaeger/OTLP/Console by setting UseTracingExporter in appsettings.json.
            var tracingExporter = configuration.GetValue<string>("UseTracingExporter")?.ToLowerInvariant();
            if (!string.IsNullOrEmpty(tracingExporter))
            {
                //open telemetry tracing
                services.AddOpenTelemetry()
                .WithTracing(tracerProviderBuilder =>
                {
                    tracerProviderBuilder
                        .AddSource(serviceName)
                        .ConfigureResource(resource => resource
                        .AddService(serviceName))
                        .SetSampler(new AlwaysOnSampler())
                        .AddHttpClientInstrumentation()
                        .AddAspNetCoreInstrumentation();
                    // Use IConfiguration binding for AspNetCore instrumentation options.
                    services.Configure<AspNetCoreInstrumentationOptions>(configuration.GetSection("AspNetCoreInstrumentation"));
                    switch (tracingExporter)
                    {
                        case "jaeger":
                            tracerProviderBuilder.AddJaegerExporter();
                            tracerProviderBuilder.ConfigureServices(services =>
                            {
                                // Use IConfiguration binding for Jaeger exporter options.
                                services.Configure<JaegerExporterOptions>(configuration.GetSection("Jaeger"));
                                // Customize the HttpClient that will be used when JaegerExporter is configured for HTTP transport.
                                services.AddHttpClient("JaegerExporter", configureClient: (client) => client.DefaultRequestHeaders.Add("X-MyCustomHeader", "value"));
                            });
                            break;
                        case "zipkin":
                            tracerProviderBuilder.AddZipkinExporter();
                            tracerProviderBuilder.ConfigureServices(services =>
                            {
                                // Use IConfiguration binding for Zipkin exporter options.
                                services.Configure<ZipkinExporterOptions>(configuration.GetSection("Zipkin"));
                            });
                            break;
                        case "otlp":
                            tracerProviderBuilder.AddOtlpExporter(otlpOptions =>
                            {
                                // Use IConfiguration directly for Otlp exporter endpoint option.
                                var config = configuration["Otlp:Endpoint"];
                                if (!string.IsNullOrEmpty(config))
                                {
                                    otlpOptions.Endpoint = new Uri(config);
                                }
                            });
                            break;
                        default:
                            tracerProviderBuilder.AddConsoleExporter();
                            break;
                    }
                });
            }
            return services;
        }
    }
}
