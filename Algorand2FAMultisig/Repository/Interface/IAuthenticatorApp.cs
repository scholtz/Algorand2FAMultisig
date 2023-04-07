using Algorand2FAMultisig.Model;

namespace Algorand2FAMultisig.Repository.Interface
{
    public interface IAuthenticatorApp
    {
        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, bool secretIsBase32 = false);

        public SetupReturn GenerateSetupCode(Algorand.Algod.Model.Account account, string accountTitleNoSpaces, string accountSecretKey, bool secretIsBase32, int qrPixelsPerModule = 3);
        
    }
}
