using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    public enum EncryptionMode 
    {
        ECB,    // Electronic Codebook 
        CBC,    // Cipher Block Chaining
        PCBC,   // Propagating Cipher Block Chaining 
        CFB,    // Cipher Feedback 
        OFB,    // Output Feedback 
        CTR,    // Counter 
        RandomDelta  // Random Delta 
    }

    public enum PaddingMode
    {
        Zeros,      // Добавление нулей (не удаляется автоматически)
        AnsiX923,   // ANSI X.9.23: нули + байт с длиной набивки
        Pkcs7,      // PKCS#7: байты со значением = длине набивки
        Iso10126    // ISO 10126: случайные байты + байт с длиной (требует RNG)
    }

    internal class CryptoAlgoritm : ISymmetricBlockCipher, IDisposable
    {
        private readonly ISymmetricBlockCipher _baseCipher;
        private readonly EncryptionMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[] _iv;
        private readonly int _blockSize;
        private readonly Dictionary<string, object> _additionalParams;

        public CryptoAlgoritm(
            byte[] key,
            EncryptionMode mode,
            PaddingMode padding,
            byte[] iv = null,
            params object[] additionalParams)
        {
            throw new NotImplementedException();
        }

        private Dictionary<string, object> ParseAdditionalParams(object[] paramsArray)
        {
            throw new NotImplementedException();
        }

        private int GetBlockSizeFromParamsOrDefault()
        {
            throw new NotImplementedException();
        }

        private byte[] GenerateDefaultIv(int keyLength)
        {
            throw new NotImplementedException();
        }

        public void Initialize(byte[] key)
        { 
            throw new NotImplementedException(); 
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            throw new NotImplementedException();
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
            throw new NotImplementedException();
        }

        public async Task<byte[]> EncryptAsync(byte[] data)
        {
            throw new NotImplementedException();
        }

        public async Task<byte[]> DecryptAsync(byte[] data)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            
        }
    }
}
