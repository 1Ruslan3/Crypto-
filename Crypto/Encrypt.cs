namespace Crypto
{ 
    public interface IFullEncryption
    {
        byte[] Encrypt(byte[] inputBlock, byte[] key);
    }
}