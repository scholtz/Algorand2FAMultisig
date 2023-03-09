namespace Algorand2FAMultisig.Model
{
    public class Multisig
    {
        public int Version { get; set; }
        public int Threshold { get; set; }
        public string[] Signators { get; set; } = new string[0];
    }
}
