using Algorand2FAMultisig.Repository.Interface;

namespace Algorand2FAMultisig.Repository.Implementation.Storage
{
    /// <summary>
    /// Storage in ram for tests
    /// </summary>
    public class StorageMock : IStorage
    {
        private readonly Dictionary<string, bool> DB = new();
        /// <summary>
        /// Clear data
        /// </summary>
        public void Clear()
        {
            DB.Clear();
        }

        /// <summary>
        /// Check if config exists
        /// </summary>
        /// <param name="primaryAccount"></param>
        /// <param name="twoFactorAccount"></param>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        public bool Exists(string primaryAccount, string twoFactorAccount, string secondaryAccount)
        {
            var key = $"{primaryAccount}-{twoFactorAccount}-{secondaryAccount}";
            return DB.ContainsKey(key);
        }
        /// <summary>
        /// Store config
        /// </summary>
        /// <param name="primaryAccount"></param>
        /// <param name="twoFactorAccount"></param>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        public bool Save(string primaryAccount, string twoFactorAccount, string secondaryAccount)
        {
            var key = $"{primaryAccount}-{twoFactorAccount}-{secondaryAccount}";
            DB[key] = true;
            return true;
        }
    }
}
