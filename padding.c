// Morgan Reilly
// Padding for SHA256

#include <stdio.h>
#include <inttypes.h> // Includes formatters for printf

uint64_t no_zeros_bytes(uint64_t no_bits)
{
    uint64_t result = 512 - (no_bits % 512ULL);

    if (result < 65)
    {
        result += 512;
    }

    result -= 72;

    return (result / 8ULL);
}

int main(int argc, char *argv[])
{

    // Expect command line arg
    if (argc != 2)
    {
        printf("Error: expected single filename as argument\n");
        return 1;
    }

    FILE *inFile = fopen(argv[1], "rb");

    // Error handling -- Can't open file
    if (!inFile)
    {
        printf("Error: couldn't open file %s. \n", argv[1]);
        return 1;
    }

    uint8_t b;
    // Keep track of all bits seen
    uint64_t noBits;

    // Try read file 1 byte at a time..
    // Read into b (& -> Address)
    // Read 1 byte, read 1 copy of bytes, from inFile
    for (noBits = 0; fread(&b, 1, 1, inFile) == 1; noBits += 8)
    {
        printf("%02" PRIx8, b);
    }

    printf("%02" PRIx8, 0x80); // Bits: 1000 0000

    for (uint64_t i = (no_zeros_bytes(noBits)); i > 0; i--)
    {
        printf("%02" PRIx8, 0x00);
    }

    printf("%016" PRIx64 "\n", noBits);

    printf("\n");

    fclose(inFile);

    return 0;
}