using System.Collections;

namespace DesAlgoritm
{
    public static class BitPermutation
    {
        public static byte[] PermuteBits(byte[] input, int[] pBox)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (pBox == null) throw new ArgumentNullException(nameof(pBox));
            int totalInputBits = input.Length * 8;
            int outputLen = pBox.Length;

            for (int i = 0; i < outputLen; i++)
            {
                int logical = pBox[i];
                if (logical < 1 || logical > totalInputBits)
                    throw new ArgumentException($"Invalid pBox[{i}] = {logical} (must be 1-{totalInputBits}).");
            }

            BitArray inputBits = new BitArray(totalInputBits);
            for (int logical = 1; logical <= totalInputBits; logical++)
            {
                int byteIdx = (logical - 1) / 8;
                int bitInByte = 7 - ((logical - 1) % 8);
                inputBits[logical - 1] = (input[byteIdx] & (1 << bitInByte)) != 0;
            }

            BitArray outputBits = new BitArray(outputLen);
            for (int outIdx = 0; outIdx < outputLen; outIdx++)
            {
                int sourceLogical = pBox[outIdx];
                outputBits[outIdx] = inputBits[sourceLogical - 1];
            }

            int outBytes = (outputLen + 7) / 8;
            byte[] output = new byte[outBytes];
            for (int logical = 1; logical <= outputLen; logical++)
            {
                int byteIdx = (logical - 1) / 8;
                int bitInByte = 7 - ((logical - 1) % 8);
                if (outputBits[logical - 1])
                    output[byteIdx] |= (byte)(1 << bitInByte);
            }

            return output;
        }
    }

    //static void Main()
    //{
    //    byte[] input = { 0b10000000, 0b00000001 };
    //    int[] pBox = { 7, 6, 5, 4, 3, 2, 1, 0 }; 
    //    bool lsbFirst = true;
    //    bool zeroBased = true;

    //    Console.WriteLine("Исходный input:");
    //    Console.WriteLine($"  input[0]: {input[0]} (0b{Convert.ToString(input[0], 2).PadLeft(8, '0')})");
    //    Console.WriteLine($"  input[1]: {input[1]} (0b{Convert.ToString(input[1], 2).PadLeft(8, '0')})");

    //    BitPermutation.PermuteBits(input, pBox, lsbFirst, zeroBased);

    //    Console.WriteLine("\nПосле перестановки (каждый байт независимо):");
    //    Console.WriteLine($"  input[0]: {input[0]} (0b{Convert.ToString(input[0], 2).PadLeft(8, '0')})"); 
    //    Console.WriteLine($"  input[1]: {input[1]} (0b{Convert.ToString(input[1], 2).PadLeft(8, '0')})"); 
    //}
}