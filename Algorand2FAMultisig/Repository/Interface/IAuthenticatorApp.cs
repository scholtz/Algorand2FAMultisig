using Algorand2FAMultisig.Model;

namespace Algorand2FAMultisig.Repository.Interface
{
    /// <summary>
    /// Auth app
    /// </summary>
    public interface IAuthenticatorApp
    {
        /// <summary>
        /// Validate pin
        /// </summary>
        /// <param name="accountSecretKey"></param>
        /// <param name="twoFactorCodeFromClient"></param>
        /// <param name="secretIsBase32"></param>
        /// <returns></returns>
        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, bool secretIsBase32 = false);
        /// <summary>
        /// Generate setup code
        /// </summary>
        /// <param name="account"></param>
        /// <param name="accountTitleNoSpaces"></param>
        /// <param name="accountSecretKey"></param>
        /// <param name="secretIsBase32"></param>
        /// <param name="qrPixelsPerModule"></param>
        /// <returns></returns>
        public SetupReturn GenerateSetupCode(Algorand.Algod.Model.Account account, string accountTitleNoSpaces, string accountSecretKey, bool secretIsBase32, int qrPixelsPerModule = 3);
        
    }
}
