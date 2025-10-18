namespace Crypto
{ 
    public interface IEncryptionRound
    {
        byte[] EncryptRound(byte[] inputBlock, byte[] key);
    }
}