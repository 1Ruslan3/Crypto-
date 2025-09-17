namespace Crypto
{
    public class FeistelNetwork : ISymmetricBlockCipher
    {
        private readonly IKeyExpansion _keyExpander;
        private readonly IEncryptionRound _roundFunction; 
        private readonly int _blockSize;
        private readonly int _halfSize; 
        private byte[][] _roundKeys;
        private bool _isInitialized;
        private bool _disposed;

        public FeistelNetwork(IKeyExpansion keyExpander, IEncryptionRound roundFunction, int blockSize = 8)
        {
            _keyExpander = keyExpander ?? throw new ArgumentNullException(nameof(keyExpander));
            _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
            if (blockSize <= 0 || blockSize % 2 != 0)
                throw new ArgumentException("Block size must be positive and even.", nameof(blockSize));
            _blockSize = blockSize;
            _halfSize = blockSize / 2;
        }


        public byte[] Decrypt(byte[] inputBlock)
        {
            ValidateInitializedAndBlock(inputBlock);
            byte[] L = new byte[_halfSize];
            byte[] R = new byte[_halfSize];
            SplitBlock(inputBlock, L, R);

            L = (byte[])L.Clone();
            R = (byte[])R.Clone();

            int numRounds = _roundKeys.Length;

            for (int i = numRounds - 1; i >= 0; i--)
            {
                byte[] F = _roundFunction.EncryptRound(L, _roundKeys[i]);

                // R_{i-1} = L_i (обратное)
                byte[] newR = (byte[])L.Clone();

                // L_{i-1} = R_i XOR F
                byte[] newL = XorBlocks(R, F);

                R = newR;
                L = newL;
            }

            return CombineBlocks(L, R);
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            ValidateInitializedAndBlock(inputBlock);
            byte[] L = new byte[_halfSize];
            byte[] R = new byte[_halfSize];
            SplitBlock(inputBlock, L, R);

            L = (byte[])L.Clone();
            R = (byte[])R.Clone();

            int numRounds = _roundKeys.Length;
            for (int i = 0; i < numRounds; i++)
            {
                // F(R, K_i)
                byte[] F = _roundFunction.EncryptRound(R, _roundKeys[i]);

                // L_{i+1} = R_i
                byte[] newL = (byte[])R.Clone();

                // R_{i+1} = L_i XOR F
                byte[] newR = XorBlocks(L, F);

                L = newL;
                R = newR;
            }

            return CombineBlocks(L, R);
        }

        public void Initialize(byte[] key)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(FeistelNetwork));
            if (_isInitialized) throw new InvalidOperationException("Already initialized. Call Reset() first.");
            if (key == null) throw new ArgumentNullException(nameof(key));

            _roundKeys = _keyExpander.ExpandKey(key);
            if (_roundKeys == null || _roundKeys.Length == 0)
                throw new InvalidOperationException("Key expansion returned empty round keys.");

            foreach (var subKey in _roundKeys)
            {
                if (subKey.Length != _halfSize)
                    throw new InvalidOperationException($"Subkey length {_halfSize} expected, but got {subKey.Length}.");
            }

            _isInitialized = true;
        }


        private void ValidateInitializedAndBlock(byte[] block)
        {
            if (!_isInitialized) throw new InvalidOperationException("Not initialized. Call Initialize(key) first.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != _blockSize)
                throw new ArgumentException($"Block length must be {_blockSize} bytes.", nameof(block));
        }

        private void SplitBlock(byte[] block, byte[] L, byte[] R)
        {
            Array.Copy(block, 0, L, 0, _halfSize);
            Array.Copy(block, _halfSize, R, 0, _halfSize);
        }

        private byte[] CombineBlocks(byte[] L, byte[] R)
        {
            byte[] full = new byte[_blockSize];
            Array.Copy(L, 0, full, 0, _halfSize);
            Array.Copy(R, 0, full, _halfSize, _halfSize);
            return full;
        }

        private byte[] XorBlocks(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
    }
}
