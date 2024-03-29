using Algorand;
using Algorand.Algod.Model.Transactions;
using Algorand2FAMultisig.Repository.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Concurrent;
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
        private readonly IStorage storage;
        private string AuthUser = "";
        private readonly ConcurrentDictionary<string, DateTimeOffset> InvalidPinAttempts = new ConcurrentDictionary<string, DateTimeOffset>();
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configuration"></param>
        /// <param name="authenticatorApp"></param>
        /// <param name="storage"></param>
        /// <exception cref="Exception"></exception>
        public MultisigController(ILogger<MultisigController> logger, IConfiguration configuration, IAuthenticatorApp authenticatorApp, IStorage storage)
        {
            this.logger = logger;
            this.configuration = configuration;
            this.authenticatorApp = authenticatorApp;
            this.storage = storage;

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
        /// To prevent brute force if hacker has stolen primary account, store time of invalid attempt
        /// </summary>
        [NonAction]
        public void SetUserInvalidPinTooManyAttempts()
        {
            var user = GetAuthUser();
            logger.LogWarning($"InvalidPinAttempt: {user}");
            InvalidPinAttempts[user] = DateTimeOffset.UtcNow;

            foreach (var item in InvalidPinAttempts.Keys)
            {
                if (InvalidPinAttempts.TryGetValue(user, out var time))
                {
                    if (time.AddHours(1) < DateTimeOffset.UtcNow)
                    {
                        // user entered invalid pin long time ago, we can remove it from ram
                        InvalidPinAttempts.TryRemove(item, out _);
                    }
                }
            }
        }

        /// <summary>
        /// To prevent brute force if hacker has stolen primary account, check if invalid attempt was very soon to new attempt
        /// </summary>
        /// <returns>If true, user can continue.. Did not enter invalid pin recently</returns>
        [NonAction]
        public bool CheckInvalidAttempt()
        {
            var user = GetAuthUser();
            if (InvalidPinAttempts.TryGetValue(user, out var time))
            {
                if (time.AddSeconds(60) > DateTimeOffset.UtcNow)
                {
                    // user entered invalid pin in short time
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// SHA256
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        [NonAction]
        public static string ComputeSHA256Hash(string text)
        {
            return BitConverter.ToString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).Replace("-", "").ToLower();
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
            return SHA256.HashData(Encoding.UTF8.GetBytes(text));
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
        public ActionResult<byte[]> PasswordAccountSign([FromForm] string password, [FromForm] byte[] unsignedTxMsgPack)
        {
            try
            {
                if (password.Length < 10) throw new Exception("Password must be at least 10 char long");
                if (unsignedTxMsgPack == null) throw new Exception("Error in signedTx");
                var tx = Algorand.Utils.Encoder.DecodeFromMsgPack<Transaction>(unsignedTxMsgPack);

                var seed = ComputeSHA256HashBytes($"{password}");
                var account = new Algorand.Algod.Model.Account(seed);
                var address = account.Address.EncodeAsString();
                logger?.LogInformation($"PasswordAccountSign:{address}");

                var signed = tx.Sign(account);
                var messagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(signed);
                return Ok(messagePack);
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
        [HttpPost("PasswordAccountSignMsig")]
        public ActionResult<byte[]> PasswordAccountSignMsig([FromForm] string password, [FromForm] byte[] signedTxMsgPack)
        {
            try
            {
                if (password.Length < 10) throw new Exception("Password must be at least 10 char long");
                var signedTxObj = Algorand.Utils.Encoder.DecodeFromMsgPack<SignedTransaction>(signedTxMsgPack) ?? throw new Exception("Error in signedTxBytes");
                if (signedTxObj.MSig == null) throw new Exception("signedTxMsgPack is not multisig transaction.");


                var seed = ComputeSHA256HashBytes($"{password}");
                var account = new Algorand.Algod.Model.Account(seed);
                var address = account.Address.EncodeAsString();
                logger?.LogInformation($"PasswordAccountSignMsig:{address}");

                var msig = new MultisigAddress(signedTxObj.MSig.Version, signedTxObj.MSig.Threshold, new List<Ed25519PublicKeyParameters>(signedTxObj.MSig.Subsigs.Select(s => s.key)));
                var signed = signedTxObj.Tx.Sign(msig, account);

                var messagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(signed);
                return Ok(messagePack);
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



                logger?.LogError($"{GetAuthUser()}:SetupAuthenticator TODO check from the DB if secondary account {secondaryAccount}");

                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);

                if (storage.Exists(GetAuthUser(), account.Address.EncodeAsString(), secondaryAccount))
                {
                    throw new Exception("You have already confirmed setup for these accounts and we cannot show you secret again. Use your primary and recovery account to rekey to new 2fa setup with different recovery account.");
                }

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
                logger?.LogInformation($"{GetAuthUser()}:TestValidateTwoFactorPIN");
                if (!CheckInvalidAttempt())
                {
                    throw new Exception("Invalid PIN. Please try again in 60 seconds.");
                }
                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);

                if (storage.Exists(GetAuthUser(), account.Address.EncodeAsString(), secondaryAccount))
                {
                    throw new Exception("You have already confirmed setup for these accounts and we cannot show you secret again. Use your primary and recovery account to rekey to new 2fa setup with different recovery account.");
                }

                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");

                bool result = authenticatorApp.ValidateTwoFactorPIN(key, UniformTxtCode(txtCode));
                if (!result) { SetUserInvalidPinTooManyAttempts(); }
                if (!result) throw new Exception("Invalid PIN. Please try again in 60 seconds.");


                if (!storage.Save(GetAuthUser(), account.Address.EncodeAsString(), secondaryAccount))
                {
                    throw new Exception("There are issues with the storage right now. Please try again later.");
                }

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

                if (!CheckInvalidAttempt())
                {
                    return Ok(false);
                }

                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");

                bool result = authenticatorApp.ValidateTwoFactorPIN(key, UniformTxtCode(txtCode));
                if (!result) { SetUserInvalidPinTooManyAttempts(); }

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
        /// <param name="signedTxMsgPack">signed Tx in msg pack</param>
        /// <param name="secondaryAccount">Recovery account</param>
        /// <returns></returns>
        [Authorize]
        [HttpPost("SignWithTwoFactorPINMsigTx")]
        public ActionResult<byte[]> SignWithTwoFactorPINMsigTx([FromForm] string txtCode, [FromForm] byte[] signedTxMsgPack, [FromForm] string secondaryAccount)
        {
            try
            {
                logger?.LogInformation($"{GetAuthUser()}:SignWithTwoFactorPINMsigTx");

                if (!CheckInvalidAttempt())
                {
                    throw new Exception("Invalid PIN. Please try again in 60 seconds.");
                }

                if (string.IsNullOrEmpty(txtCode))
                {
                    throw new ArgumentException($"'{nameof(txtCode)}' cannot be null or empty.", nameof(txtCode));
                }


                if (signedTxMsgPack == null || signedTxMsgPack.Length == 0) throw new Exception("signedTx is empty");
                var signedTxObj = Algorand.Utils.Encoder.DecodeFromMsgPack<SignedTransaction>(signedTxMsgPack) ?? throw new Exception("Error in signedTxBytes");
                if (signedTxObj.MSig == null) throw new Exception("signedTxMsgPack is not multisig transaction.");

                var seed = CreateSeed(secondaryAccount);
                var account = new Algorand.Algod.Model.Account(seed);
                var key = ComputeSHA256Hash($"{account.Address}-{configuration["Algo:Mnemonic"]}");

                bool result = authenticatorApp.ValidateTwoFactorPIN(key, UniformTxtCode(txtCode));
                if (!result) { SetUserInvalidPinTooManyAttempts(); }

                if (!result) throw new Exception("Invalid PIN. Please try again in 60 seconds.");


                var msig = new MultisigAddress(signedTxObj.MSig.Version, signedTxObj.MSig.Threshold, new List<Ed25519PublicKeyParameters>(signedTxObj.MSig.Subsigs.Select(s => s.key)));

                var signed = signedTxObj.Tx.Sign(msig, account);
                var newSignedTxObj = MsigExtension.MsigExtension.MergeMultisigTransactions(signed, signedTxObj);
                var messagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(newSignedTxObj);
                return Ok(messagePack);
            }
            catch (Exception exc)
            {
                logger?.LogError(exc.Message);
                return BadRequest(new ProblemDetails() { Detail = exc.Message });
            }
        }
        /// <summary>
        /// For testing purposes only
        /// </summary>
        [NonAction]
        public void Clear()
        {
            InvalidPinAttempts.Clear();
        }
    }
}