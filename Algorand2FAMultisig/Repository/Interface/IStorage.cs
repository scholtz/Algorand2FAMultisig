namespace Algorand2FAMultisig.Repository.Interface
{
    /// <summary>
    /// Storage interface.
    /// </summary>
    public interface IStorage
    {
        /// <summary>
        /// Check if configuration of accounts already exists
        /// </summary>
        /// <param name="primaryAccount"></param>
        /// <param name="twoFactorAccount"></param>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        public bool Exists(string primaryAccount, string twoFactorAccount, string secondaryAccount);
        /// <summary>
        /// Stores the configuration of accounts
        /// </summary>
        /// <param name="primaryAccount"></param>
        /// <param name="twoFactorAccount"></param>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        public bool Save(string primaryAccount, string twoFactorAccount, string secondaryAccount);
    }
}
