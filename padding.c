// Morgan Reilly
// Padding for SHA256

#include <stdio.h>
#include <inttypes.h> // Includes formatters for printf

// Preprocessing
// Create union 512int blocks
union block {
    uint64_t sixfour[8]; // 64 * 8 = 512
    uint32_t threetwo[16]; // 32 * 16 = 512
    uint8_t eight[64]; // 8 * 64 = 512
};


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

    // Rather than read on the fly
    // have union block
    union block M;

    uint8_t i;

    // MAIN ALGORITHM LOOP
    // Try read file 1 byte at a time..
    // Read into b (& -> Address)
    // Read 1 byte, read 1 copy of bytes, from inFile
    // CHANGED:
    // added: i = 0
    // modified: &b -> &M.eight[i]
    for (noBits = 0, i = 0; fread(&M.eight[i], 1, 1, inFile) == 1; noBits += 8)
    {
        printf("%02" PRIx8, M.eight[i]);
    }

    printf("%02" PRIx8, 0x80); // Bits: 1000 0000

    // PADDING TO BE DONE ON THE FLY
    for (uint64_t i = (no_zeros_bytes(noBits)); i > 0; i--)
    {
        printf("%02" PRIx8, 0x00);
    }

    printf("%016" PRIx64 "\n", noBits);

    printf("\n");

    fclose(inFile);

    return 0;
}