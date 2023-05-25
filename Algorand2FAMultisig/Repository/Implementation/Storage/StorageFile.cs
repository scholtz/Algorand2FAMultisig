using Algorand2FAMultisig.Controllers;
using Algorand2FAMultisig.Repository.Interface;

namespace Algorand2FAMultisig.Repository.Implementation.Storage
{
    /// <summary>
    /// Simple file persistant storage
    /// </summary>
    public class StorageFile : IStorage
    {
        private readonly string Folder;
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configuration"></param>
        public StorageFile(ILogger<StorageFile> logger, IConfiguration configuration)
        {
            Folder = configuration["Algo:Folder"] ?? "Data";
            if (!Directory.Exists(Folder))
            {
                logger.LogWarning($"Creating folder {Folder}");
                Directory.CreateDirectory(Folder);
            }
        }
        /// <summary>
        /// Check if configuration exists
        /// </summary>
        /// <param name="primaryAccount"></param>
        /// <param name="twoFactorAccount"></param>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        public bool Exists(string primaryAccount, string twoFactorAccount, string secondaryAccount)
        {
            var key = $"{Folder}/{primaryAccount}-{twoFactorAccount}-{secondaryAccount}.txt";
            return File.Exists(key);
        }
        /// <summary>
        /// Store file to filesystem
        /// </summary>
        /// <param name="primaryAccount"></param>
        /// <param name="twoFactorAccount"></param>
        /// <param name="secondaryAccount"></param>
        /// <returns></returns>
        public bool Save(string primaryAccount, string twoFactorAccount, string secondaryAccount)
        {
            var key = $"{Folder}/{primaryAccount}-{twoFactorAccount}-{secondaryAccount}.txt";
            File.WriteAllText(key, DateTimeOffset.UtcNow.ToString("R"));
            return true;
        }
    }
}
