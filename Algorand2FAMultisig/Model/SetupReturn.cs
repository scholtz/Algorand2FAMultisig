namespace Algorand2FAMultisig.Model
{

    /// <summary>
    /// 2FA setup by Authentication application
    /// </summary>
    public class SetupReturn
    {
        /// <summary>
        /// User's personal address for this service
        /// </summary>
        public string Address { get; set; } = "";
        /// <summary>
        /// QR code entry value for manual input to Authentication application
        /// </summary>
        public string ManualEntryKey { get; internal set; } = "";
        /// <summary>
        /// QR code
        /// </summary>
        public string QrCodeSetupImageUrl { get; internal set; } = "";
        /// <summary>
        /// Account
        /// </summary>
        public string Account { get; internal set; } = "";
    }
}
