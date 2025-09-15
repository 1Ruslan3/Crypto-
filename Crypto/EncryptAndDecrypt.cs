namespace Crypto
{
    public interface ISymmetricBlockCipher
    {
        void Initialize(byte[] key);

        byte[] Encrypt(byte[] inputBlock);

        byte[] Decrypt(byte[] inputBlock);

    }
}