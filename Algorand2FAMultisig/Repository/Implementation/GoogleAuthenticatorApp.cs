using Algorand2FAMultisig.Model;
using Algorand2FAMultisig.Repository.Interface;
using Google.Authenticator;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using static System.Runtime.CompilerServices.RuntimeHelpers;

namespace Algorand2FAMultisig.Repository.Implementation
{
    /// <summary>
    /// Google auth app
    /// </summary>
    public class GoogleAuthenticatorApp : IAuthenticatorApp
    {
        private readonly IConfiguration configuration;
        private readonly TwoFactorAuthenticator tfa = new();
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configuration"></param>
        public GoogleAuthenticatorApp(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        /// <summary>
        /// Setup code
        /// </summary>
        /// <param name="account"></param>
        /// <param name="accountTitleNoSpaces"></param>
        /// <param name="accountSecretKey"></param>
        /// <param name="secretIsBase32"></param>
        /// <param name="qrPixelsPerModule"></param>
        /// <returns></returns>
        public SetupReturn GenerateSetupCode(Algorand.Algod.Model.Account account, string accountTitleNoSpaces, string accountSecretKey, bool secretIsBase32, int qrPixelsPerModule = 3)
        {
            SetupCode setupInfo = tfa.GenerateSetupCode(configuration["Algo:TwoFactorName"], accountTitleNoSpaces, accountSecretKey, secretIsBase32, qrPixelsPerModule);

            var ret = new SetupReturn()
            {
                Address = account.Address.EncodeAsString(),
                Account = setupInfo.Account,
                ManualEntryKey = setupInfo.ManualEntryKey,
                QrCodeSetupImageUrl = setupInfo.QrCodeSetupImageUrl,
            };
            return ret;
        }

        /// <summary>
        /// Validate pin
        /// </summary>
        /// <param name="accountSecretKey"></param>
        /// <param name="twoFactorCodeFromClient"></param>
        /// <param name="secretIsBase32"></param>
        /// <returns></returns>
        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, bool secretIsBase32 = false)
        {
            return tfa.ValidateTwoFactorPIN(accountSecretKey, twoFactorCodeFromClient, secretIsBase32);
        }
    }
}
