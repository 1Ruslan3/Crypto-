namespace Crypto
{
    internal class Encrypt
    {
        public interface IFullEncryption
        {
            byte[] Encrypt(byte[] inputBlock, byte[] key);
        }
    }
}
