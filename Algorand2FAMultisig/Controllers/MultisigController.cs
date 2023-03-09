using Algorand;
using Algorand.Algod.Model.Transactions;
using Google.Authenticator;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using static System.Runtime.CompilerServices.RuntimeHelpers;

namespace Algorand2FAMultisig.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class MultisigController : ControllerBase
    {

        private readonly ILogger<MultisigController> logger;
        private readonly IConfiguration configuration;
        private readonly string key;
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configuration"></param>
        /// <exception cref="Exception"></exception>
        public MultisigController(ILogger<MultisigController> logger, IConfiguration configuration)
        {
            this.logger = logger;
            this.configuration = configuration;
            if (string.IsNullOrEmpty(configuration["Algo:Mnemonic"])) throw new Exception("Please configure Algo:Mnemonic in secrets");
            _ = new Algorand.Algod.Model.Account(configuration["Algo:Mnemonic"]); // test if mnemonic is ok
            key = ComputeSHA256Hash(configuration["Algo:Mnemonic"]);
        }
        public static string ComputeSHA256Hash(string text)
        {
            using var sha256 = SHA256.Create();
            return BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "");
        }
        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [HttpGet("GetAccount")]
        public IActionResult GetAddress()
        {
            try
            {
                var account = new Algorand.Algod.Model.Account(configuration["Algo:Mnemonic"]);
                return Ok(account.Address.EncodeAsString());
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Ask for QR code
        /// 
        /// In X-2FA header is setup object
        /// in X-Address header is the configured address
        /// </summary>
        /// <param name="accountTitleNoSpaces">The user account or source system. It is shown in the Authenticator app</param>
        /// <returns></returns>
        [HttpPost("SetupGoogleAuthenticator")]
        public IActionResult SetupGoogleAuthenticator([FromForm] string accountTitleNoSpaces)
        {
            try
            {
                TwoFactorAuthenticator tfa = new();

                SetupCode setupInfo = tfa.GenerateSetupCode(configuration["Algo:TwoFactorName"], accountTitleNoSpaces, key, false, 3);
                string qrCodeImageUrl = setupInfo.QrCodeSetupImageUrl;

                // data:image/png;base64,iVBORw..
                var b = Convert.FromBase64String(qrCodeImageUrl[(qrCodeImageUrl.IndexOf(",") + 1)..]);
                Response.Headers.Add("X-2FA", JsonConvert.SerializeObject(setupInfo));
                var account = new Algorand.Algod.Model.Account(configuration["Algo:Mnemonic"]);
                Response.Headers.Add("X-Address", account.Address.EncodeAsString());
                return File(b, "image/png");
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Test 2FA auth
        /// </summary>
        /// <param name="txtCode"></param>
        /// <returns></returns>
        [HttpPost("TestValidateTwoFactorPIN")]
        public IActionResult TestValidateTwoFactorPIN([FromForm] string txtCode)
        {
            try
            {
                TwoFactorAuthenticator tfa = new();
                bool result = tfa.ValidateTwoFactorPIN(key, txtCode);

                return Ok(result);
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Do multisig signing and return SignedTransaction json object 
        /// </summary>
        /// <param name="txtCode"></param>
        /// <param name="msigConfig"></param>
        /// <param name="tx"></param>
        /// <returns></returns>
        [HttpPost("SignValidateTwoFactorPIN")]
        public IActionResult SignValidateTwoFactorPIN([FromForm] string txtCode, [FromForm] Model.Multisig msigConfig, [FromForm] SignedTransaction tx)
        {
            try
            {
                TwoFactorAuthenticator tfa = new();
                bool result = tfa.ValidateTwoFactorPIN(key, txtCode);
                if (!result) throw new Exception("Invalid PIN");

                var msig = new MultisigAddress(msigConfig.Version, msigConfig.Threshold, new List<Ed25519PublicKeyParameters>(msigConfig.Signators.Select(a =>
                {
                    var addr = new Address(a);
                    return new Ed25519PublicKeyParameters(addr.Bytes, 0);
                })));
                var account = new Algorand.Algod.Model.Account(configuration["Algo:Mnemonic"]);

                return Ok(tx.AppendMultisigTransaction(msig, account));

            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Do multisig signing with json object from base64 and return SignedTransaction json object with signature
        /// </summary>
        /// <param name="txtCode"></param>
        /// <param name="msigConfig"></param>
        /// <param name="signedTx"></param>
        /// <returns></returns>
        [HttpPost("SignValidateTwoFactorPINBase64Tx")]
        public IActionResult SignValidateTwoFactorPINBase64Tx([FromForm] string txtCode, [FromForm] Model.Multisig msigConfig, [FromForm] string signedTx)
        {
            try
            {
                if (string.IsNullOrEmpty(signedTx)) throw new Exception("signedTx is empty");
                var signedTxBytes = Convert.FromBase64String(signedTx);
                if (signedTxBytes == null) throw new Exception("Error in signedTx");
                var signedTxObj = JsonConvert.DeserializeObject<SignedTransaction>(Encoding.UTF8.GetString(signedTxBytes));
                if (signedTxObj == null) throw new Exception("Error in signedTxBytes");
                TwoFactorAuthenticator tfa = new();
                bool result = tfa.ValidateTwoFactorPIN(key, txtCode);
                if (!result) throw new Exception("Invalid PIN");
                var msig = new MultisigAddress(msigConfig.Version, msigConfig.Threshold, new List<Ed25519PublicKeyParameters>(msigConfig.Signators.Select(a =>
                {
                    var addr = new Address(a);
                    return new Ed25519PublicKeyParameters(addr.Bytes, 0);
                })));
                var account = new Algorand.Algod.Model.Account(configuration["Algo:Mnemonic"]);
                var newSignedTxObj = signedTxObj.AppendMultisigTransaction(msig, account);
                return Ok(Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(newSignedTxObj))));
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
    }
}