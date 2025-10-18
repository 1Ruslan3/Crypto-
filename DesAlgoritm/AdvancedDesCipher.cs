using System.Security.Cryptography;
using System.Text;

namespace DesAlgoritm
{
    #region ciphermode
    public enum CipherMode
    {
        ECB,        // Electronic Codebook
        CBC,        // Cipher Block Chaining
        PCBC,       // Propagating Cipher Block Chaining
        CFB,        // Cipher Feedback
        OFB,        // Output Feedback
        CTR,        // Counter
       // RandomDelta 
    }
    #endregion

    #region paddingmode
    public enum PaddingMode
    {
        Zeros,      
        ANSIX923,   
        PKCS7,     
        ISO10126    
    }
    #endregion

    public class AdvancedDesCipher : IDisposable
    {
        #region fields
        private readonly DesCipher _des;
        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;
        private byte[] _iv;
        private ulong _counter;
        private bool _disposed;
        private Random _random;
        #endregion

        #region constructor
        public AdvancedDesCipher()
        {
            _des = new DesCipher();
            _random = new Random();
        }
        #endregion

        #region methods
        public void Initialize(byte[] key, CipherMode cipherMode, PaddingMode paddingMode, byte[] iv = null)
        {
            if (key == null || key.Length != 8)
                throw new ArgumentException("Ключ DES должен быть 8 байт");

            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _des.Initialize(key);

            if (iv != null && iv.Length == 8)
            {
                _iv = (byte[])iv.Clone();
            }
            else
            {
                _iv = GenerateRandomIV();
            }

            _counter = 0;
        }

        public byte[] Encrypt(byte[] data)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(AdvancedDesCipher));
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] paddedData = ApplyPadding(data);

            switch (_cipherMode)
            {
                case CipherMode.ECB: return EncryptECB(paddedData);
                case CipherMode.CBC: return EncryptCBC(paddedData);
                case CipherMode.PCBC: return EncryptPCBC(paddedData);
                case CipherMode.CFB: return EncryptCFB(paddedData);
                case CipherMode.OFB: return EncryptOFB(paddedData);
                case CipherMode.CTR: return EncryptCTR(paddedData);
                //case CipherMode.RandomDelta: return EncryptRandomDelta(paddedData);
                default: throw new NotSupportedException($"Режим {_cipherMode} не поддерживается");
            }
        }
        public byte[] EncryptBlock(byte[] block)
        {
            if (block == null || block.Length != 8)
                throw new ArgumentException("Block must be 8 bytes for direct DES encryption.");
            return _des.Encrypt(block);
        }
        public byte[] Decrypt(byte[] data)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(AdvancedDesCipher));
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length % 8 != 0 && _cipherMode != CipherMode.CFB && _cipherMode != CipherMode.OFB && _cipherMode != CipherMode.CTR)
                throw new ArgumentException("Данные должны быть кратны 8 байтам для выбранного режима");

            byte[] decryptedData;

            switch (_cipherMode)
            {
                case CipherMode.ECB: decryptedData = DecryptECB(data); break;
                case CipherMode.CBC: decryptedData = DecryptCBC(data); break;
                case CipherMode.PCBC: decryptedData = DecryptPCBC(data); break;
                case CipherMode.CFB: decryptedData = DecryptCFB(data); break;
                case CipherMode.OFB: decryptedData = DecryptOFB(data); break;
                case CipherMode.CTR: decryptedData = DecryptCTR(data); break;
                //case CipherMode.RandomDelta: decryptedData = DecryptRandomDelta(data); break;
                default: throw new NotSupportedException($"Режим {_cipherMode} не поддерживается");
            }

            return RemovePadding(decryptedData);
        }
        #endregion

        #region Реализации режимов шифрования

        private byte[] EncryptECB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(data, i, block, 0, 8);
                byte[] encrypted = _des.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, 8);
            }
            return result;
        }

        private byte[] DecryptECB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(data, i, block, 0, 8);
                byte[] decrypted = _des.Decrypt(block);
                Array.Copy(decrypted, 0, result, i, 8);
            }
            return result;
        }

        private byte[] EncryptCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previous = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(data, i, block, 0, 8);

                for (int j = 0; j < 8; j++)
                    block[j] ^= previous[j];

                byte[] encrypted = _des.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, 8);
                previous = encrypted;
            }
            return result;
        }

        private byte[] DecryptCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previous = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(data, i, block, 0, 8);

                byte[] decrypted = _des.Decrypt(block);

                for (int j = 0; j < 8; j++)
                    decrypted[j] ^= previous[j];

                Array.Copy(decrypted, 0, result, i, 8);
                previous = block;
            }
            return result;
        }

        private byte[] EncryptPCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previousInput = (byte[])_iv.Clone();
            byte[] previousOutput = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(data, i, block, 0, 8);

                byte[] originalBlock = (byte[])block.Clone();

                for (int j = 0; j < 8; j++)
                    block[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);

                byte[] encrypted = _des.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, 8);

                previousInput = originalBlock;
                previousOutput = encrypted;
            }
            return result;
        }

        private byte[] DecryptPCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previousInput = (byte[])_iv.Clone();
            byte[] previousOutput = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(data, i, block, 0, 8);

                byte[] decrypted = _des.Decrypt(block);

                for (int j = 0; j < 8; j++)
                    decrypted[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);

                Array.Copy(decrypted, 0, result, i, 8);

                previousInput = decrypted;
                previousOutput = block;
            }
            return result;
        }

        private byte[] EncryptCFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] shiftRegister = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i++)
            {
                byte[] encrypted = _des.Encrypt(shiftRegister);
                result[i] = (byte)(data[i] ^ encrypted[0]);

                Array.Copy(shiftRegister, 1, shiftRegister, 0, 7);
                shiftRegister[7] = result[i];
            }
            return result;
        }

        private byte[] DecryptCFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] shiftRegister = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i++)
            {
                byte[] encrypted = _des.Encrypt(shiftRegister);
                result[i] = (byte)(data[i] ^ encrypted[0]);

                Array.Copy(shiftRegister, 1, shiftRegister, 0, 7);
                shiftRegister[7] = data[i];
            }
            return result;
        }

        private byte[] EncryptOFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += 8)
            {
                feedback = _des.Encrypt(feedback);

                int bytesToProcess = Math.Min(8, data.Length - i);
                for (int j = 0; j < bytesToProcess; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ feedback[j]);
                }
            }
            return result;
        }

        private byte[] DecryptOFB(byte[] data)
        {
            return EncryptOFB(data);
        }

        private byte[] EncryptCTR(byte[] data)
        {
            byte[] result = new byte[data.Length];
            ulong counter = _counter;

            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] counterBlock = BitConverter.GetBytes(counter);
                byte[] nonce = new byte[8];
                Array.Copy(_iv, 0, nonce, 0, 4);
                Array.Copy(counterBlock, 0, nonce, 4, 4);

                byte[] encryptedCounter = _des.Encrypt(nonce);

                int bytesToProcess = Math.Min(8, data.Length - i);
                for (int j = 0; j < bytesToProcess; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ encryptedCounter[j]);
                }
                counter++;
            }
            return result;
        }

        private byte[] DecryptCTR(byte[] data)
        {
            return EncryptCTR(data);
        }

        //private byte[] EncryptRandomDelta(byte[] data)
        //{
        //    byte[] result = new byte[data.Length];
        //    byte[] delta = GenerateRandomDelta();

        //    for (int i = 0; i < data.Length; i += 8)
        //    {
        //        byte[] block = new byte[8];
        //        Array.Copy(data, i, block, 0, 8);

        //        for (int j = 0; j < 8; j++)
        //            block[j] ^= delta[j];

        //        byte[] encrypted = _des.Encrypt(block);
        //        Array.Copy(encrypted, 0, result, i, 8);

        //        delta = UpdateDelta(delta, encrypted);
        //    }
        //    return result;
        //}

        //private byte[] DecryptRandomDelta(byte[] data)
        //{
        //    byte[] result = new byte[data.Length];
        //    byte[] delta = GenerateRandomDelta();

        //    for (int i = 0; i < data.Length; i += 8)
        //    {
        //        byte[] block = new byte[8];
        //        Array.Copy(data, i, block, 0, 8);

        //        byte[] decrypted = _des.Decrypt(block);

        //        for (int j = 0; j < 8; j++)
        //            decrypted[j] ^= delta[j];

        //        Array.Copy(decrypted, 0, result, i, 8);

        //        delta = UpdateDelta(delta, block);
        //    }
        //    return result;
        //}

        #endregion

        #region padding methods

        private byte[] ApplyPadding(byte[] data)
        {
            int blockSize = 8;
            int padLength = blockSize - (data.Length % blockSize);
            if (padLength == 0) padLength = blockSize;

            byte[] padded = new byte[data.Length + padLength];
            Array.Copy(data, 0, padded, 0, data.Length);

            switch (_paddingMode)
            {
                case PaddingMode.Zeros:
                    // Уже заполнено нулями по умолчанию
                    break;

                case PaddingMode.ANSIX923:
                    for (int i = data.Length; i < padded.Length - 1; i++)
                        padded[i] = 0;
                    padded[padded.Length - 1] = (byte)padLength;
                    break;

                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < padded.Length; i++)
                        padded[i] = (byte)padLength;
                    break;

                case PaddingMode.ISO10126:
                    for (int i = data.Length; i < padded.Length - 1; i++)
                        padded[i] = (byte)_random.Next(256);
                    padded[padded.Length - 1] = (byte)padLength;
                    break;
            }

            return padded;
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (data.Length == 0) return data;

            int padLength;
            switch (_paddingMode)
            {
                case PaddingMode.Zeros:
                    padLength = 0;
                    for (int i = data.Length - 1; i >= 0 && data[i] == 0; i--)
                        padLength++;

                    return data;

                case PaddingMode.ANSIX923:
                case PaddingMode.ISO10126:
                    padLength = data[data.Length - 1];
                    if (padLength > 8 || padLength <= 0 || padLength > data.Length)
                        return data;
                    break;

                case PaddingMode.PKCS7:
                    padLength = data[data.Length - 1];
                    if (padLength > 8 || padLength <= 0 || padLength > data.Length)
                        return data;
                    for (int i = data.Length - padLength; i < data.Length; i++)
                    {
                        if (data[i] != padLength)
                            return data;
                    }
                    break;

                default:
                    return data;
            }

            byte[] result = new byte[data.Length - padLength];
            Array.Copy(data, 0, result, 0, result.Length);
            return result;
        }

        #endregion

        #region helper methods

        private byte[] GenerateRandomIV()
        {
            byte[] iv = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

        private byte[] GenerateRandomDelta()
        {
            byte[] delta = new byte[8];
            _random.NextBytes(delta);
            return delta;
        }

        private byte[] UpdateDelta(byte[] currentDelta, byte[] encryptedBlock)
        {
            byte[] newDelta = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                newDelta[i] = (byte)(currentDelta[i] ^ encryptedBlock[i]);
            }
            return newDelta;
        }

        #endregion

        #region IDisposibale
        public void Dispose()
        {
            if (!_disposed)
            {
                _des?.Dispose();
                _disposed = true;
            }
        }
        #endregion
    }
    #region Демонстрация и примеры

    public class DesDemo
    {
        public static void RunFullDemo()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("=== ПОЛНАЯ ДЕМОНСТРАЦИЯ DES С РЕЖИМАМИ ШИФРОВАНИЯ И НАБИВКИ ===\n");

            TestBasicDes();
            TestCipherModes();
            TestPaddingModes();
            TestFileEncryption();
            TestPerformance();

            Console.WriteLine("\n=== ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА ===");
        }

        private static void TestBasicDes()
        {
            Console.WriteLine("1. БАЗОВЫЙ ТЕСТ DES");

            byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] expected = { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

            using (var des = new DesCipher())
            {
                des.Initialize(key);

                byte[] ciphertext = des.Encrypt(plaintext);
                byte[] decrypted = des.Decrypt(ciphertext);

                 Console.WriteLine($"Ключ: {BitConverter.ToString(key)}");
                Console.WriteLine($"Открытый текст: {BitConverter.ToString(plaintext)}");
                Console.WriteLine($"Шифротекст: {BitConverter.ToString(ciphertext)}");
                Console.WriteLine($"Ожидаемый: {BitConverter.ToString(expected)}");
                Console.WriteLine($"Совпадение с ожидаемым: {ciphertext.SequenceEqual(expected)}");
                Console.WriteLine($"Дешифрование корректно: {plaintext.SequenceEqual(decrypted)}");
            }
        }

        private static void TestCipherModes()
        {
            Console.WriteLine("\n2. ТЕСТ РЕЖИМОВ ШИФРОВАНИЯ");

            byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            string testMessage = "Тестовое сообщение для проверки режимов шифрования DES!";
            byte[] testData = Encoding.UTF8.GetBytes(testMessage);

            foreach (CipherMode mode in Enum.GetValues(typeof(CipherMode)))
            {
                using (var des = new AdvancedDesCipher())
                {
                    des.Initialize(key, mode, PaddingMode.PKCS7);

                    byte[] encrypted = des.Encrypt(testData);
                    byte[] decrypted = des.Decrypt(encrypted);

                    string result = Encoding.UTF8.GetString(decrypted);
                    bool success = testMessage == result;

                    Console.WriteLine($"{mode.ToString().PadRight(12)}: Успех = {success}, " +
                                    $"Размер = {encrypted.Length} байт");
                }
            }
        }

        private static void TestPaddingModes()
        {
            Console.WriteLine("\n3. ТЕСТ РЕЖИМОВ НАБИВКИ");

            byte[] key = { 0x25, 0x46, 0x68, 0x8A, 0xAC, 0xCE, 0xE0, 0x02 };
            byte[] testData = { 0x01, 0x02, 0x03, 0x04, 0x05 }; // 5 байт

            Console.WriteLine($"Исходные данные: {BitConverter.ToString(testData)} ({testData.Length} байт)");

            foreach (PaddingMode paddingMode in Enum.GetValues(typeof(PaddingMode)))
            {
                using (var des = new AdvancedDesCipher())
                {
                    des.Initialize(key, CipherMode.CBC, paddingMode);

                    byte[] encrypted = des.Encrypt(testData);
                    byte[] decrypted = des.Decrypt(encrypted);

                    bool success = testData.SequenceEqual(decrypted);

                    Console.WriteLine($"{paddingMode.ToString().PadRight(10)}: Успех = {success}, " +
                                    $"Размер = {encrypted.Length} байт");
                }
            }
        }

        private static void TestFileEncryption()
        {
            Console.WriteLine("\n4. ШИФРОВАНИЕ ФАЙЛОВ");

            CreateTestFiles();

            byte[] key = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

            string[] files = { "test.txt", "image.bin", "data.bin" };

            foreach (string file in files)
            {
                if (File.Exists(file))
                {
                    byte[] fileData = File.ReadAllBytes(file);

                    using (var des = new AdvancedDesCipher())
                    {
                        des.Initialize(key, CipherMode.CBC, PaddingMode.PKCS7);

                        byte[] encrypted = des.Encrypt(fileData);
                        byte[] decrypted = des.Decrypt(encrypted);

                        File.WriteAllBytes($"{file}.enc", encrypted);
                        File.WriteAllBytes($"{file}.dec", decrypted);

                        Console.WriteLine($"{file}: {fileData.Length} -> {encrypted.Length} -> {decrypted.Length} байт, " +
                                        $"Корректность: {fileData.SequenceEqual(decrypted)}");
                    }
                }
            }
        }

        private static void TestPerformance()
        {
            Console.WriteLine("\n5. ТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ");

            byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] data = new byte[1024 * 1024]; // 1 MB
            new Random(42).NextBytes(data);

            var modes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.CFB };

            foreach (var mode in modes)
            {
                using (var des = new AdvancedDesCipher())
                {
                    des.Initialize(key, mode, PaddingMode.PKCS7);

                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    byte[] encrypted = des.Encrypt(data);
                    stopwatch.Stop();
                    long encryptTime = stopwatch.ElapsedMilliseconds;

                    stopwatch.Restart();
                    byte[] decrypted = des.Decrypt(encrypted);
                    stopwatch.Stop();
                    long decryptTime = stopwatch.ElapsedMilliseconds;

                    bool valid = data.SequenceEqual(decrypted);
                    double speed = (data.Length * 2.0) / (encryptTime + decryptTime) / 1024; // KB/s

                    Console.WriteLine($"{mode.ToString().PadRight(6)}: " +
                                    $"Шифр = {encryptTime}ms, " +
                                    $"Дешифр = {decryptTime}ms, " +
                                    $"Скорость = {speed:F0} KB/s, " +
                                    $"Корректность = {valid}");
                }
            }
        }

        private static void CreateTestFiles()
        {
            File.WriteAllText("test.txt",
                "Это тестовый файл для демонстрации шифрования DES.\n" +
                "Содержит текст на русском и английском: Hello World!\n" +
                "Вторая строка с данными.\n" +
                "Третья строка для тестирования.");

            byte[] imageData = new byte[512];
            for (int i = 0; i < imageData.Length; i++)
            {
                imageData[i] = (byte)(i % 256);
            }
            File.WriteAllBytes("image.bin", imageData);

            byte[] patternData = new byte[256];
            byte[] pattern = { 0x00, 0xFF, 0x55, 0xAA };
            for (int i = 0; i < patternData.Length; i++)
            {
                patternData[i] = pattern[i % pattern.Length];
            }
            File.WriteAllBytes("data.bin", patternData);

            Console.WriteLine("Созданы тестовые файлы: test.txt, image.bin, data.bin");
        }
    }

    #endregion

    class Program
    {
       static void Main(string[] args)
       {  
           DesDemo.RunFullDemo();

           Console.WriteLine("\nНажмите любую клавишу для выхода...");
           Console.ReadKey();
       }
    }

}
