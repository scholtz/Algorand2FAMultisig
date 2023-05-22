using Algorand;
using Algorand.Algod.Model.Transactions;
using Algorand2FAMultisig.Repository.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Algorand2FAMultisig.Controllers
{
    /// <summary>
    /// API controller
    /// </summary>
    [ApiController]
    [Route("v1/[controller]")]
    public class MultisigController : ControllerBase
    {

        private readonly ILogger<MultisigController> logger;
        private readonly IConfiguration configuration;
        private readonly IAuthenticatorApp authenticatorApp;
        private string AuthUser = "";
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configuration"></param>
        /// <param name="authenticatorApp"></param>
        /// <exception cref="Exception"></exception>
        public MultisigController(ILogger<MultisigController> logger, IConfiguration configuration, IAuthenticatorApp authenticatorApp)
        {
            this.logger = logger;
            this.configuration = configuration;
            this.authenticatorApp = authenticatorApp;

            if (string.IsNullOrEmpty(configuration["Algo:Mnemonic"])) throw new Exception("Please configure Algo:Mnemonic in secrets");
            // _ = new Algorand.Algod.Model.Account(configuration["Algo:Mnemonic"]); // in Algo:Mnemonic is stored key for generating accounts
        }
        /// <summary>
        /// For testing purposes only
        /// </summary>
        [NonAction]
        public void SetAuthUser(string AuthUser)
        {
            this.AuthUser = AuthUser;
        }

        /// <summary>
        /// For testing purposes only
        /// </summary>
        [NonAction]
        public string GetAuthUser()
        {
            return User?.Identity?.Name ?? AuthUser;
        }

        /// <summary>
        /// SHA256
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        [NonAction]
        public static string ComputeSHA256Hash(string text)
        {
            using var sha256 = SHA256.Create();
            return BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").ToLower();
        }
        /// <summary>
        /// Unifies the code.. Trim and remove -.
        /// </summary>
        /// <param name="txtCode"></param>
        /// <returns></returns>
        [NonAction]
        public static string UniformTxtCode(string txtCode)
        {
            return txtCode.Trim().Replace("-", "");
        }
        /// <summary>
        /// SHA256
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        [NonAction]
        public static byte[] ComputeSHA256HashBytes(string text)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
        }
        /// <summary>
        /// Create seed for authenticated user and sedondary account with configuration password
        /// </summary>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        [NonAction]
        private byte[] CreateSeed(string secondaryAccount)
        {
            return ComputeSHA256HashBytes($"{GetAuthUser()}-{configuration["Algo:Mnemonic"]}-{secondaryAccount}");
        }
        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [HttpGet("GetMasterPasswordHash")]
        public IActionResult GetMasterPasswordHash()
        {
            try
            {
                logger?.LogInformation($"GetMasterPasswordHash");
                return Ok(ComputeSHA256Hash($"{configuration["Algo:Mnemonic"]}"));
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [HttpGet("GetRealm")]
        public IActionResult GetRealm()
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:GetRealm");
                return Ok($"{configuration["AlgorandAuthentication:Realm"]}");
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [HttpPost("PasswordAccountAddress")]
        public ActionResult<string> PasswordAccountAddress([FromForm] string password)
        {
            try
            {
                if (password.Length < 10) throw new Exception("Password must be at least 10 char long");
                var seed = ComputeSHA256HashBytes($"{password}");
                var account = new Algorand.Algod.Model.Account(seed);
                var address = account.Address.EncodeAsString();
                logger?.LogError($"PasswordAccountAddress:{address}");
                return Ok(address);
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }


        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [HttpPost("PasswordAccountSign")]
        public ActionResult<string> PasswordAccountSign([FromForm] string password, [FromForm] string unsignedTxMsgPack)
        {
            try
            {
                if (password.Length < 10) throw new Exception("Password must be at least 10 char long");


                var signedTxBytes = Convert.FromBase64String(unsignedTxMsgPack);
                if (signedTxBytes == null) throw new Exception("Error in signedTx");
                var tx = Algorand.Utils.Encoder.DecodeFromMsgPack<Transaction>(signedTxBytes);

                var seed = ComputeSHA256HashBytes($"{password}");
                var account = new Algorand.Algod.Model.Account(seed);
                var address = account.Address.EncodeAsString();
                logger?.LogError($"PasswordAccountSign:{address}");

                var signed = tx.Sign(account);
                var messagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(signed);
                return Ok(Convert.ToBase64String(messagePack));
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }

        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [Authorize]
        [HttpGet("GetAddress/{secondaryAccount}")]
        public ActionResult<string> GetAddress([FromRoute] string secondaryAccount)
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:GetAddress");
                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                return Ok(account.Address.EncodeAsString());
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Shows the configured account for this 2FA system
        /// </summary>
        /// <returns></returns>
        [Authorize]
        [HttpGet("MyAddress")]
        public ActionResult<string> MyAddress()
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:MyAddress");
                return Ok(GetAuthUser());
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// Ask for QR code
        /// </summary>
        /// <param name="accountTitleNoSpaces">The user account or source system. It is shown in the Authenticator app</param>
        /// <param name="secondaryAccount">Recovery account</param>
        /// <returns>Model.SetupReturn</returns>
        [Authorize]
        [HttpPost("SetupAuthenticator")]
        public ActionResult<Model.SetupReturn> SetupAuthenticator([FromForm] string accountTitleNoSpaces, [FromForm] string secondaryAccount)
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:SetupAuthenticator");

                // TODO check from the DB if secondary account has been setup for this account already (it is stored at ConfirmSetupAuthenticator method)
                // if secondary account exists, deny this request

                logger?.LogError($"{GetAuthUser()}:SetupAuthenticator TODO check from the DB if secondary account {secondaryAccount}");

                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");
                var ret = authenticatorApp.GenerateSetupCode(account, accountTitleNoSpaces, key, false, 3);


                return Ok(ret);
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
        /// <param name="txtCode">Code from authenticator app</param>
        /// <param name="secondaryAccount">Recovery account</param>
        /// <returns>Returns the address to be added to multisig</returns>
        [Authorize]
        [HttpPost("ConfirmSetupAuthenticator")]
        public ActionResult<string> ConfirmSetupAuthenticator([FromForm] string txtCode, [FromForm] string secondaryAccount)
        {
            try
            {
                // TODO check from the DB if secondary account has been setup for this account already
                // if secondary account exists, deny this request

                logger?.LogInformation($"{GetAuthUser()}:TestValidateTwoFactorPIN");

                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");

                bool result = authenticatorApp.ValidateTwoFactorPIN(key, UniformTxtCode(txtCode));

                // TODO .. save secondaryAccount

                return Ok(account.Address.EncodeAsString());
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
        /// <param name="txtCode">Code from authenticator app</param>
        /// <param name="secondaryAccount">Recovery account</param>
        /// <returns></returns>
        [Authorize]
        [HttpPost("TestValidateTwoFactorPIN")]
        public ActionResult<bool> TestValidateTwoFactorPIN([FromForm] string txtCode, [FromForm] string secondaryAccount)
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:TestValidateTwoFactorPIN");

                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");

                bool result = authenticatorApp.ValidateTwoFactorPIN(key, UniformTxtCode(txtCode));

                return Ok(result);
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }

        /// <summary>
        /// Do multisig signing with msg pack object from base64 and return SignedTransaction json object in msgpack base64 with signature
        /// </summary>
        /// <param name="txtCode">PIN from authenticator app</param>
        /// <param name="msigConfigBase64">msigConfig in base64</param>
        /// <param name="signedTxMsgPack">signed Tx in msg pack</param>
        /// <param name="secondaryAccount">Recovery account</param>
        /// <returns></returns>
        [Authorize]
        [HttpPost("SignValidateTwoFactorPINBase64MsgPackTx")]
        public ActionResult<string> SignValidateTwoFactorPINBase64MsgPackTx([FromForm] string txtCode, [FromForm] string msigConfigBase64, [FromForm] string signedTxMsgPack, [FromForm] string secondaryAccount)
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:SignValidateTwoFactorPINBase64MessagePackTx");

                if (string.IsNullOrEmpty(txtCode))
                {
                    throw new ArgumentException($"'{nameof(txtCode)}' cannot be null or empty.", nameof(txtCode));
                }

                if (msigConfigBase64 is null)
                {
                    throw new ArgumentNullException(nameof(msigConfigBase64));
                }

                if (string.IsNullOrEmpty(signedTxMsgPack))
                {
                    throw new ArgumentException($"'{nameof(signedTxMsgPack)}' cannot be null or empty.", nameof(signedTxMsgPack));
                }
                var msigConfig = JsonConvert.DeserializeObject<Model.Multisig>(msigConfigBase64);

                if (msigConfig == null || msigConfig.Version <= 0 || msigConfig.Threshold <= 0)
                {
                    throw new ArgumentException($"'{nameof(signedTxMsgPack)}' cannot be null or empty. Deserialized object is null.", nameof(signedTxMsgPack));
                }

                if (string.IsNullOrEmpty(signedTxMsgPack)) throw new Exception("signedTx is empty");
                var signedTxBytes = Convert.FromBase64String(signedTxMsgPack);
                if (signedTxBytes == null) throw new Exception("Error in signedTx");

                var signedTxObj = Algorand.Utils.Encoder.DecodeFromMsgPack<SignedTransaction>(signedTxBytes);
                if (signedTxObj == null) throw new Exception("Error in signedTxBytes");
                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");

                bool result = authenticatorApp.ValidateTwoFactorPIN(key, UniformTxtCode(txtCode));
                if (!result) throw new Exception("Invalid PIN");
                var msig = new MultisigAddress(msigConfig.Version, msigConfig.Threshold, new List<Ed25519PublicKeyParameters>(msigConfig.Signators.Select(a =>
                {
                    var addr = new Address(a);
                    return new Ed25519PublicKeyParameters(addr.Bytes, 0);
                })));

                var signed = signedTxObj.Tx.Sign(msig, account);
                var newSignedTxObj = MsigExtension.MsigExtension.MergeMultisigTransactions(signed, signedTxObj);
                var messagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(newSignedTxObj);
                return Ok(Convert.ToBase64String(messagePack));
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
    }
}