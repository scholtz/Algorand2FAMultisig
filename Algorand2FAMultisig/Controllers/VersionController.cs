using Algorand2FAMultisig.Extension;
using Microsoft.AspNetCore.Mvc;
namespace Algorand2FAMultisig.Controllers
{
    /// <summary>
    /// This controller returns version of the current api
    /// </summary>
    [ApiController]
    [Route("v1/version")]
    public class VersionController : ControllerBase
    {
        /// <summary>
        /// Returns version of the current api
        /// 
        /// For development purposes it returns version of assembly, for production purposes it returns string build by pipeline which contains project information, pipeline build version, assembly version, and build date
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public ActionResult<Version> Get()
        {
            try
            {
                var ret = VersionExtensions.GetVersion(
                    Program.InstanceId,
                    Program.Started,
                    GetType()?.Assembly?.GetName()?.Version?.ToString()
                );
                return Ok(ret);
            }
            catch (Exception exc)
            {
                return BadRequest(new ProblemDetails() { Detail = exc.Message + (exc.InnerException != null ? $";\n{exc.InnerException.Message}" : "") + "\n" + exc.StackTrace, Title = exc.Message, Type = exc.GetType().ToString() });
            }
        }
    }
}
