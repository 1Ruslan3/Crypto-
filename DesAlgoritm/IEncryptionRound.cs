namespace DesAlgoritm
{ 
    public interface IEncryptionRound
    {
        byte[] EncryptRound(byte[] inputBlock, byte[] key);
    }
}