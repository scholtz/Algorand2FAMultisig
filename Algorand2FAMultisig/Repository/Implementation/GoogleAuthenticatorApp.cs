using Algorand2FAMultisig.Model;
using Algorand2FAMultisig.Repository.Interface;
using Google.Authenticator;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using static System.Runtime.CompilerServices.RuntimeHelpers;

namespace Algorand2FAMultisig.Repository.Implementation
{
    public class GoogleAuthenticatorApp : IAuthenticatorApp
    {
        private readonly IConfiguration configuration;
        private readonly TwoFactorAuthenticator tfa = new();
        public GoogleAuthenticatorApp(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
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

        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, bool secretIsBase32 = false)
        {
            return tfa.ValidateTwoFactorPIN(accountSecretKey, twoFactorCodeFromClient, secretIsBase32);
        }
    }
}
