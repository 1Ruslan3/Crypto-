using System.Text;
using System.Security.Cryptography;

namespace Crypto {

    #region DealKeyExpander (реализация IKeyExpansion)
    public class DealKeyExpander : IKeyExpansion
    {
        private readonly int _rounds;
        private readonly byte[] _RStar = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }; // фиксированный DES-ключ R*
        
        public DealKeyExpander(int rounds)
        {
            if (rounds != 6 && rounds != 8)
                throw new ArgumentException("DEAL supports 6 or 8 rounds only (DEAL-128/192/256).", nameof(rounds));
            _rounds = rounds;
        }

        public byte[][] ExpandKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("DEAL key must be 128, 192, or 256 bits (16/24/32 bytes).");

            // Разбиваем мастер-ключ на куски по 8 байт
            int keyParts = key.Length / 8;
            byte[][] K = new byte[keyParts][];
            for (int i = 0; i < keyParts; i++)
            {
                K[i] = new byte[8];
                Array.Copy(key, i * 8, K[i], 0, 8);
            }

            byte[][] R = new byte[_rounds][]; // раундовые ключи

            // Используем временный DES с фиксированным ключом R*
            using (var des = new AdvancedDesCipher())
            {
                des.Initialize(_RStar, CipherMode.ECB, PaddingMode.Zeros);

                if (_rounds == 6)
                {
                    // DEAL-128 или DEAL-192
                    R[0] = des.EncryptBlock(K[0]); // R1 = E_{R*}(K1)
                    R[1] = des.EncryptBlock(Xor(K[1 % keyParts], R[0])); // R2 = E_{R*}(K2 ⊕ R1)
                    R[2] = des.EncryptBlock(Xor(K[0], R[1], new byte[] { 1 })); // R3 = E_{R*}(K1 ⊕ R2 ⊕ 1)
                    R[3] = des.EncryptBlock(Xor(K[1 % keyParts], R[2], new byte[] { 2 })); // R4 = E_{R*}(K2 ⊕ R3 ⊕ 2)
                    R[4] = des.EncryptBlock(Xor(K[0], R[3], new byte[] { 3 })); // R5 = E_{R*}(K1 ⊕ R4 ⊕ 3)
                    R[5] = des.EncryptBlock(Xor(K[1 % keyParts], R[4], new byte[] { 4 })); // R6 = E_{R*}(K2 ⊕ R5 ⊕ 4)
                }
                else
                {
                    // DEAL-256
                    R[0] = des.Encrypt(K[0]);
                    R[1] = des.Encrypt(Xor(K[1], R[0]));
                    R[2] = des.Encrypt(Xor(K[2], R[1]));
                    R[3] = des.Encrypt(Xor(K[3], R[2]));
                    R[4] = des.Encrypt(Xor(K[0], R[3], new byte[] { 1 }));
                    R[5] = des.Encrypt(Xor(K[1], R[4], new byte[] { 2 }));
                    R[6] = des.Encrypt(Xor(K[2], R[5], new byte[] { 3 }));
                    R[7] = des.Encrypt(Xor(K[3], R[6], new byte[] { 4 }));
                }
            }

            return R;
        }

        private byte[] Xor(byte[] a, byte[] b)
        {
            byte[] res = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                res[i] = (byte)(a[i] ^ b[i]);
            return res;
        }

        private byte[] Xor(byte[] a, byte[] b, byte[] c)
        {
            byte[] res = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                res[i] = (byte)(a[i] ^ b[i] ^ c[0]);
            return res;
        }
    }
    #endregion
    
    #region DesRoundAdapter
    public class DesRoundAdapter : IEncryptionRound, IDisposable
    {
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private AdvancedDesCipher _desCipher;

        private readonly bool _ownCipher;    
        public DesRoundAdapter(AdvancedDesCipher externalCipher = null, CipherMode mode = CipherMode.ECB, PaddingMode padding = PaddingMode.Zeros)
        {
            _mode = mode;
            _padding = padding;
            if (externalCipher != null)
            {
                _desCipher = externalCipher;
                _ownCipher = false;
            }
            else
            {
                _desCipher = new AdvancedDesCipher();
                _ownCipher = true;
            }

        }    
        public byte[] EncryptRound(byte[] inputBlock, byte[] key)
        {
            if (inputBlock == null)
                throw new ArgumentNullException(nameof(inputBlock));
            if (key == null || key.Length != 8)
                throw new ArgumentException("Round key must be 8 bytes.", nameof(key));

            byte[] desBlock = new byte[8];
            Array.Copy(inputBlock, desBlock, Math.Min(8, inputBlock.Length));

            using (var des = new AdvancedDesCipher())
            {
                des.Initialize(key, CipherMode.ECB, PaddingMode.Zeros);
                byte[] encrypted = des.Encrypt(desBlock);

                byte[] result = new byte[inputBlock.Length];
                Array.Copy(encrypted, result, inputBlock.Length);
                return result;
            }
        }
        public void Dispose()
        {
            if (_ownCipher)
            {
                _desCipher?.Dispose();
                _desCipher = null;
            }
        }

    }
    #endregion
    
    #region DealCipher

    public class DealCipher : IDisposable
    {
        private readonly FeistelNetwork _feistel;
        private readonly DealKeyExpander _expander;
        private readonly DesRoundAdapter _adapter;
        private readonly int _blockSize;
        private bool _initialized;
        public DealCipher(int rounds = 16, int blockSize = 8)
        {
            if (blockSize <= 0 || blockSize % 2 != 0) throw new ArgumentException("Block size must be even", nameof(blockSize));
            _blockSize = blockSize;
            _expander = new DealKeyExpander(rounds);
            _adapter = new DesRoundAdapter(); // создаёт собственный AdvancedDesCipher внутри
            _feistel = new FeistelNetwork(_expander, _adapter, blockSize);
        }
        public void Initialize(byte[] masterKey)
        {
            if (masterKey == null)
                throw new ArgumentNullException(nameof(masterKey));

            int rounds;
            switch (masterKey.Length)
            {
                case 16: rounds = 6; break; // DEAL-128
                case 24: rounds = 6; break; // DEAL-192
                case 32: rounds = 8; break; // DEAL-256
                default:
                    throw new ArgumentException("DEAL key must be 16, 24, or 32 bytes (128/192/256 bits).");
            }

            var expander = new DealKeyExpander(rounds);
            var adapter = new DesRoundAdapter();
            var feistel = new FeistelNetwork(expander, adapter, _blockSize);

            _feistel.Reset();
            _feistel.Initialize(masterKey);
            _initialized = true;
        }

        public byte[] Encrypt(byte[] plain)
        {
            if (!_initialized) throw new InvalidOperationException("Not initialized");
            if (plain == null) throw new ArgumentNullException(nameof(plain));

            byte[] padded = ApplyPkcs7(plain, _blockSize);
            byte[] cipher = new byte[padded.Length];

            for (int i = 0; i < padded.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(padded, i, block, 0, _blockSize);
                byte[] cb = _feistel.Encrypt(block);
                Array.Copy(cb, 0, cipher, i, _blockSize);
            }
            return cipher;
        }
        public byte[] Decrypt(byte[] cipher)
        {
            if (!_initialized) throw new InvalidOperationException("Not initialized");
            if (cipher == null) throw new ArgumentNullException(nameof(cipher));
            if (cipher.Length % _blockSize != 0) throw new ArgumentException("Cipher length must be multiple of block size");

            byte[] plainPadded = new byte[cipher.Length];

            for (int i = 0; i < cipher.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(cipher, i, block, 0, _blockSize);
                byte[] pb = _feistel.Decrypt(block);
                Array.Copy(pb, 0, plainPadded, i, _blockSize);
            }

            return RemovePkcs7(plainPadded);
        }
        public void Reset()
        {
            _feistel.Reset();
            _initialized = false;
        }

        public void Dispose()
        {
            _adapter?.Dispose();
            _feistel?.Reset();
        }

        #region PKCS7 padding helpers
        private static byte[] ApplyPkcs7(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0) padLen = blockSize;
            byte[] res = new byte[data.Length + padLen];
            Array.Copy(data, 0, res, 0, data.Length);
            for (int i = data.Length; i < res.Length; i++) res[i] = (byte)padLen;
            return res;
        }

        private static byte[] RemovePkcs7(byte[] data)
        {
            if (data == null || data.Length == 0) return data;
            int padLen = data[data.Length - 1];
            if (padLen <= 0 || padLen > data.Length) throw new CryptographicException("Invalid PKCS7 padding");

            for (int i = data.Length - padLen; i < data.Length; i++)
            {
                if (data[i] != padLen) throw new CryptographicException("Invalid PKCS7 padding");
            }
            byte[] res = new byte[data.Length - padLen];
            Array.Copy(data, 0, res, 0, res.Length);
            return res;
        }
        #endregion
    }
    #endregion

    #region Пример использования
    public static class Program
    {
        public static void Main()
        {
            byte[] key128 = Encoding.ASCII.GetBytes("12345678ABCDEFGH"); 
            byte[] plaintext = Encoding.UTF8.GetBytes("DuRa!!!");

            using (var deal = new DealCipher(rounds: 6, blockSize: 8))
            {
                deal.Initialize(key128);

                byte[] cipher = deal.Encrypt(plaintext);
                byte[] recovered = deal.Decrypt(cipher);

                Console.WriteLine("Key length : " + key128.Length * 8 + " bits");
                Console.WriteLine("Ciphertext : " + BitConverter.ToString(cipher));
                Console.WriteLine("Recovered  : " + Encoding.UTF8.GetString(recovered));
            }
        }
        private static bool ByteArrayEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null) return true;
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }
    #endregion
}