using System.Collections;

public static class BitPermutation
{
    public static void PermuteBits(byte[] input, int[] pBox, bool lsbFirst, bool zeroBased)
    {
        if (input == null) 
            throw new ArgumentNullException(nameof(input));
        if (pBox == null) 
            throw new ArgumentNullException(nameof(pBox));
        if (pBox.Length != 8) 
            throw new ArgumentException("P-box length must be exactly 8 (for one byte).", nameof(pBox));

        const int bitsPerByte = 8;

        for (int targetIdx = 0; targetIdx < bitsPerByte; targetIdx++)
        {
            int sourceLogical = pBox[targetIdx];
            int minLogical = zeroBased ? 0 : 1;
            int maxLogical = zeroBased ? bitsPerByte - 1 : bitsPerByte;
            if (sourceLogical < minLogical || sourceLogical > maxLogical)
                throw new ArgumentException($"Invalid source logical position {sourceLogical} in pBox[{targetIdx}].", nameof(pBox));
        }

        for (int byteIndex = 0; byteIndex < input.Length; byteIndex++)
        {
            byte currentByte = input[byteIndex];

            BitArray oldBits = new BitArray(bitsPerByte);
            for (int j = 0; j < bitsPerByte; j++) 
            {
                oldBits[j] = (currentByte & (1 << j)) != 0;
            }

            BitArray newBits = new BitArray(bitsPerByte);
            for (int targetIdx = 0; targetIdx < bitsPerByte; targetIdx++)
            {
                int targetLogical = zeroBased ? targetIdx : targetIdx + 1;
                int sourceLogical = pBox[targetIdx];

                int targetPhysical = LogicalToPhysical(targetLogical, bitsPerByte, lsbFirst, zeroBased);
                int sourcePhysical = LogicalToPhysical(sourceLogical, bitsPerByte, lsbFirst, zeroBased);

                newBits[targetPhysical] = oldBits[sourcePhysical];
            }

            byte newByte = 0;
            for (int j = 0; j < bitsPerByte; j++)
            {
                if (newBits[j])
                    newByte |= (byte)(1 << j);
            }
            input[byteIndex] = newByte;
        }
    }

    private static int LogicalToPhysical(int logical, int totalBits, bool lsbFirst, bool zeroBased)
    {
        int zeroBasedLogical = zeroBased ? logical : logical - 1;
        if (zeroBasedLogical < 0 || zeroBasedLogical >= totalBits)
            throw new ArgumentException($"Invalid logical position {logical} (out of range 0 to {totalBits - 1}).");

        return lsbFirst ? zeroBasedLogical : totalBits - 1 - zeroBasedLogical;
    }

    static void Main()
    {
        byte[] input = { 0b10000000, 0b00000001 };
        int[] pBox = { 7, 6, 5, 4, 3, 2, 1, 0 }; 
        bool lsbFirst = true;
        bool zeroBased = true;

        Console.WriteLine("Исходный input:");
        Console.WriteLine($"  input[0]: {input[0]} (0b{Convert.ToString(input[0], 2).PadLeft(8, '0')})");
        Console.WriteLine($"  input[1]: {input[1]} (0b{Convert.ToString(input[1], 2).PadLeft(8, '0')})");

        BitPermutation.PermuteBits(input, pBox, lsbFirst, zeroBased);

        Console.WriteLine("\nПосле перестановки (каждый байт независимо):");
        Console.WriteLine($"  input[0]: {input[0]} (0b{Convert.ToString(input[0], 2).PadLeft(8, '0')})"); 
        Console.WriteLine($"  input[1]: {input[1]} (0b{Convert.ToString(input[1], 2).PadLeft(8, '0')})"); 
    }
}