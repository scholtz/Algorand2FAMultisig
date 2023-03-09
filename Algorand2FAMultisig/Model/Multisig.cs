namespace Algorand2FAMultisig.Model
{
    /// <summary>
    /// Multisig comm object
    /// </summary>
    public class Multisig
    {
        /// <summary>
        /// Version 1
        /// </summary>
        public int Version { get; set; }
        /// <summary>
        /// Multisig threshold - number of signatures required
        /// </summary>
        public int Threshold { get; set; }
        /// <summary>
        /// Signators addresses
        /// </summary>
        public string[] Signators { get; set; } = Array.Empty<string>();
    }
}
