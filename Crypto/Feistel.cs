namespace Crypto
{
    public class FeistelNetwork : ISymmetricBlockCipher
    {
        private readonly IKeyExpansion _keyExpander;
        private readonly IEncryptionRound _roundFunction;
        private readonly int _blockSize;
        private readonly int _halfSize;
        private byte[][] _roundKeys;
        public bool IsInitialized { get; private set; }

        public FeistelNetwork(IKeyExpansion keyExpander, IEncryptionRound roundFunction, int blockSize = 8)
        {
            _keyExpander = keyExpander ?? throw new ArgumentNullException(nameof(keyExpander));
            _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
            if (blockSize <= 0 || blockSize % 2 != 0) throw new ArgumentException("Block size must be even.", nameof(blockSize));
            _blockSize = blockSize;
            _halfSize = blockSize / 2;
        }

        public void Initialize(byte[] key)
        {
            if (IsInitialized) throw new InvalidOperationException("Already initialized.");
            _roundKeys = _keyExpander.ExpandKey(key) ?? throw new InvalidOperationException("Key expansion failed.");
            IsInitialized = true;
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            if (!IsInitialized) throw new InvalidOperationException("Not initialized.");
            if (inputBlock == null || inputBlock.Length != _blockSize) throw new ArgumentException("Invalid block.");

            byte[] L = new byte[_halfSize];
            byte[] R = new byte[_halfSize];
            Split(inputBlock, L, R);

            for (int i = 0; i < _roundKeys.Length; i++)
            {
                byte[] F = _roundFunction.EncryptRound(R, _roundKeys[i]);
                byte[] newL = (byte[])R.Clone();
                byte[] newR = Xor(L, F);
                L = newL;
                R = newR;
            }

            // return R || L (final swap)
            return Combine(R, L);
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
            if (!IsInitialized) throw new InvalidOperationException("Not initialized.");
            if (inputBlock == null || inputBlock.Length != _blockSize) throw new ArgumentException("Invalid block.");

            byte[] L = new byte[_halfSize];
            byte[] R = new byte[_halfSize];
            Split(inputBlock, L, R);

            for (int i = _roundKeys.Length - 1; i >= 0; i--)
            {
                byte[] F = _roundFunction.EncryptRound(R, _roundKeys[i]);
                byte[] newL = (byte[])R.Clone();
                byte[] newR = Xor(L, F);
                L = newL;
                R = newR;
            }

            return Combine(R, L);
        }

        public void Reset()
        {
            if (_roundKeys != null)
            {
                foreach (var k in _roundKeys) if (k != null) Array.Clear(k, 0, k.Length);
                _roundKeys = null;
            }
            IsInitialized = false;
        }

        void ISymmetricBlockCipher.Initialize(byte[] key) => Initialize(key);
        byte[] ISymmetricBlockCipher.Encrypt(byte[] block) => Encrypt(block);
        byte[] ISymmetricBlockCipher.Decrypt(byte[] block) => Decrypt(block);
        void ISymmetricBlockCipher.Reset() => Reset();

        private void Split(byte[] block, byte[] L, byte[] R)
        {
            Array.Copy(block, 0, L, 0, _halfSize);
            Array.Copy(block, _halfSize, R, 0, _halfSize);
        }

        private byte[] Combine(byte[] L, byte[] R)
        {
            byte[] outb = new byte[_blockSize];
            Array.Copy(L, 0, outb, 0, _halfSize);
            Array.Copy(R, 0, outb, _halfSize, _halfSize);
            return outb;
        }

        private byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) throw new ArgumentException("Length mismatch");
            byte[] res = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) res[i] = (byte)(a[i] ^ b[i]);
            return res;
        }
    }
}