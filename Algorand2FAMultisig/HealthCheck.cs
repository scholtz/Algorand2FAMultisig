using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Algorand2FAMultisig
{
    /// <summary>
    /// Check health status
    /// </summary>
    public class HealthCheck : IHealthCheck
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                return Task.FromResult(HealthCheckResult.Healthy("A healthy result."));
            }
            catch (Exception)
            {
                return Task.FromResult(
                    new HealthCheckResult(
                        context.Registration.FailureStatus, "An unhealthy result."));
            }
        }
    }
}
