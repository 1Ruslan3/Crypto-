namespace Crypto
{
    public interface IKeyExpansion
    {
        byte[][] ExpandKey(byte[] key);
    }
}