using System.Collections;

namespace Crypto
{
    public class DesCipher : ISymmetricBlockCipher, IDisposable
    {
        #region fields
        private readonly FeistelNetwork _feistel;
        private bool _disposed;
        #endregion

        #region constructor
        public DesCipher()
        {
            _feistel = new FeistelNetwork(new DesKeyExpansion(), new DesRoundFunction(), 8);
        }
        #endregion

        #region Nested class
        public class DesKeyExpansion : IKeyExpansion
        {
            #region box

            private static readonly int[] PC1 = {
            57,49,41,33,25,17,9,1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,21,13,5,28,20,12,4
        };

            private static readonly int[] PC2 = {
            14,17,11,24,1,5,3,28,15,6,21,10,
            23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,
            44,49,39,56,34,53,46,42,50,36,29,32
        };

            private static readonly int[] Shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

            #endregion

            #region methods

            public byte[][] ExpandKey(byte[] key)
            {
                if (key == null || key.Length != 8)
                    throw new ArgumentException("DES key must be 8 bytes.");

                byte[] pc1Key = BitPermutation.PermuteBits(key, PC1);

                byte[] C = new byte[4];
                byte[] D = new byte[4];
                ExtractLogicalBits(pc1Key, 1, 28, C);
                ExtractLogicalBits(pc1Key, 29, 28, D);

                byte[][] subKeys = new byte[16][];

                for (int round = 0; round < 16; round++)
                {
                    RotateLogicalBits(C, 28, Shifts[round]);
                    RotateLogicalBits(D, 28, Shifts[round]);

                    byte[] cd = new byte[7];
                    PackLogicalBits(C, 1, 28, cd, 1);
                    PackLogicalBits(D, 1, 28, cd, 29);

                    subKeys[round] = BitPermutation.PermuteBits(cd, PC2);
                }

                return subKeys;
            }

            private void ExtractLogicalBits(byte[] source, int startLogical, int numBits, byte[] dest)
            {
                int totalSourceBits = source.Length * 8;
                BitArray srcBits = new BitArray(totalSourceBits);

                for (int logical = 1; logical <= totalSourceBits; logical++)
                {
                    int bidx = (logical - 1) / 8;
                    int bitInByte = 7 - ((logical - 1) % 8);
                    srcBits[logical - 1] = (source[bidx] & (1 << bitInByte)) != 0;
                }

                Array.Clear(dest, 0, dest.Length);

                for (int i = 0; i < numBits; i++)
                {
                    int srcLogical = startLogical + i;
                    int destLogical = i + 1;
                    int destByte = (destLogical - 1) / 8;
                    int destBitInByte = 7 - ((destLogical - 1) % 8);

                    if (srcBits[srcLogical - 1])
                        dest[destByte] |= (byte)(1 << destBitInByte);
                }
            }

            private void PackLogicalBits(byte[] source, int sourceStartLogical, int numBits, byte[] dest, int destStartLogical)
            {
                int totalSourceBits = source.Length * 8;
                BitArray srcBits = new BitArray(totalSourceBits);

                for (int logical = 1; logical <= totalSourceBits; logical++)
                {
                    int bidx = (logical - 1) / 8;
                    int bitInByte = 7 - ((logical - 1) % 8);
                    srcBits[logical - 1] = (source[bidx] & (1 << bitInByte)) != 0;
                }

                int totalDestBits = dest.Length * 8;

                for (int i = 0; i < numBits; i++)
                {
                    int srcLogical = sourceStartLogical + i;
                    int destLogical = destStartLogical + i;
                    int destByte = (destLogical - 1) / 8;
                    int destBitInByte = 7 - ((destLogical - 1) % 8);

                    if (srcBits[srcLogical - 1])
                        dest[destByte] |= (byte)(1 << destBitInByte);
                    else
                        dest[destByte] &= (byte)~(1 << destBitInByte);
                }
            }

            private void RotateLogicalBits(byte[] block, int numBits, int shift)
            {
                BitArray bits = new BitArray(numBits);
                for (int logical = 1; logical <= numBits; logical++)
                {
                    int bidx = (logical - 1) / 8;
                    int bitInByte = 7 - ((logical - 1) % 8);
                    bits[logical - 1] = (block[bidx] & (1 << bitInByte)) != 0;
                }

                BitArray rotated = new BitArray(numBits);
                for (int i = 0; i < numBits; i++)
                    rotated[i] = bits[(i + shift) % numBits];

                Array.Clear(block, 0, block.Length);
                for (int logical = 1; logical <= numBits; logical++)
                {
                    int bidx = (logical - 1) / 8;
                    int bitInByte = 7 - ((logical - 1) % 8);
                    if (rotated[logical - 1])
                        block[bidx] |= (byte)(1 << bitInByte);
                }
            }

            #endregion
        }

        public class DesRoundFunction : IEncryptionRound
        {
            #region box

            private static readonly int[] E = {
            32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
            16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
        };

            private static readonly int[] P = {
            16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,
            19,13,30,6,22,11,4,25
        };

            private static readonly int[,,] S = new int[8, 4, 16] {
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7}, {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8}, {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0}, {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10}, {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5}, {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15}, {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8}, {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1}, {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7}, {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15}, {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9}, {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4}, {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9}, {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6}, {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14}, {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11}, {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8}, {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6}, {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1}, {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6}, {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2}, {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7}, {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2}, {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8}, {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };

            #endregion

            #region methods

            public byte[] EncryptRound(byte[] inputBlock, byte[] roundKey)
            {
                if (inputBlock == null || roundKey == null) throw new ArgumentNullException();
                if (inputBlock.Length != 4 || roundKey.Length != 6)
                    throw new ArgumentException("DES F: input 4 bytes, key 6 bytes.");

                byte[] expanded = BitPermutation.PermuteBits(inputBlock, E);

                for (int i = 0; i < 6; i++)
                    expanded[i] ^= roundKey[i];

                byte[] sOutput = new byte[4];
                int bitIdx = 1;

                for (int box = 0; box < 8; box++)
                {
                    int b1 = GetBit(expanded, bitIdx++) ? 1 : 0;
                    int b2 = GetBit(expanded, bitIdx++) ? 1 : 0;
                    int b3 = GetBit(expanded, bitIdx++) ? 1 : 0;
                    int b4 = GetBit(expanded, bitIdx++) ? 1 : 0;
                    int b5 = GetBit(expanded, bitIdx++) ? 1 : 0;
                    int b6 = GetBit(expanded, bitIdx++) ? 1 : 0;

                    int row = (b1 << 1) | b6;
                    int col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5;

                    int sVal = S[box, row, col];

                    int outStart = box * 4 + 1;
                    SetBit(sOutput, outStart + 0, (sVal & 8) != 0);
                    SetBit(sOutput, outStart + 1, (sVal & 4) != 0);
                    SetBit(sOutput, outStart + 2, (sVal & 2) != 0);
                    SetBit(sOutput, outStart + 3, (sVal & 1) != 0);
                }

                byte[] pOut = BitPermutation.PermuteBits(sOutput, P);
                return pOut;
            }

            private static bool GetBit(byte[] data, int logical)
            {
                int bidx = (logical - 1) / 8;
                int bitInByte = 7 - ((logical - 1) % 8);
                return (data[bidx] & (1 << bitInByte)) != 0;
            }

            private static void SetBit(byte[] data, int logical, bool val)
            {
                int bidx = (logical - 1) / 8;
                int bitInByte = 7 - ((logical - 1) % 8);
                if (val)
                    data[bidx] |= (byte)(1 << bitInByte);
                else
                    data[bidx] &= (byte)~(1 << bitInByte);
            }

            #endregion
        }
        #endregion

        #region box
        private static readonly int[] IP = {
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
        };

        private static readonly int[] FP = {
            40,8,48,16,56,24,64,32,
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25
        };
        #endregion

        #region methods
        public void Initialize(byte[] key)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DesCipher));
            _feistel.Initialize(key);
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DesCipher));
            if (inputBlock == null || inputBlock.Length != 8)
                throw new ArgumentException("Block must be 8 bytes.");
            if (!_feistel.IsInitialized)
                throw new InvalidOperationException("Not initialized.");

            var ipBlock = BitPermutation.PermuteBits(inputBlock, IP);
            var feistelOut = _feistel.Encrypt(ipBlock);
            var fpOut = BitPermutation.PermuteBits(feistelOut, FP);
            return fpOut;
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DesCipher));
            if (inputBlock == null || inputBlock.Length != 8)
                throw new ArgumentException("Block must be 8 bytes.");
            if (!_feistel.IsInitialized)
                throw new InvalidOperationException("Not initialized.");

            var ipBlock = BitPermutation.PermuteBits(inputBlock, IP);
            var feistelOut = _feistel.Decrypt(ipBlock);
            var fpOut = BitPermutation.PermuteBits(feistelOut, FP);
            return fpOut;
        }

        public void Reset() => _feistel.Reset();
        #endregion

        #region IDisposable
        public void Dispose()
        {
            Reset();
            _disposed = true;
        }
        #endregion
    }

    // class Program
    // {
    //     static void Main()
    //     {
    //         Console.WriteLine("=== Тестирование алгоритма DES ===");

    //         byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    //         byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    //         byte[] expected = { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

    //         Console.WriteLine("Ключ: " + BitConverter.ToString(key));
    //         Console.WriteLine("Открытый текст: " + BitConverter.ToString(plaintext));
    //         Console.WriteLine("Ожидаемый шифртекст: " + BitConverter.ToString(expected));

    //         try
    //         {
    //             using (var des = new DesCipher())
    //             {
    //                 des.Initialize(key);

    //                 byte[] ciphertext = des.Encrypt(plaintext);
    //                 Console.WriteLine("\nПолученный шифртекст: " + BitConverter.ToString(ciphertext));
    //                 Console.WriteLine("Совпадает с ожидаемым: " + ciphertext.SequenceEqual(expected));

    //                 byte[] decrypted = des.Decrypt(ciphertext);
    //                 Console.WriteLine("Дешифрованный текст: " + BitConverter.ToString(decrypted));
    //                 Console.WriteLine("Совпадает с исходным: " + plaintext.SequenceEqual(decrypted));
    //             }

    //             Console.WriteLine("\nТестирование завершено успешно!");
    //         }
    //         catch (Exception ex)
    //         {
    //             Console.WriteLine($"Ошибка: {ex.Message}");
    //         }

    //         Console.ReadKey();
    //     }
    // }
}