// Morgan Reilly
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//
// -- The Secure Hash Algorithm 256-bit version --
#pragma region IMPORTS
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h> // Includes formatters for printf
#pragma endregion

#pragma region PREPROCESSING SETUP
// Preprocessing
// Create union 512int blocks
union block {
    uint64_t sixfour[8];   // 64 * 8 = 512 -- 8 64bit intger array
    uint32_t threetwo[16]; // 32 * 16 = 512 -- 16 32bit integer array
    uint8_t eight[64];     // 8 * 64 = 512 -- 64 8bit integer array
};
#pragma endregion

#pragma region PARSE STATUS
// Represent current parse status
enum flag
{
    READ, // Not EOF -- Read OG file
    PAD0, // Pad with 0's
    // PAD1, // Read all to eof and fill block
    FINISH
};
#pragma endregion

#pragma region CONSTANTS &FUNCTIONS
// 32-bit constants -- Section 4.2.2
const uint32_t K[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Choose
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    // Section 4.1.2
    return (x & y) ^ (~x & z);
}

// Majority
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    // Section 4.1.2
    return (x & y) ^ (x & z) ^ (y & z);
}

// Shift right -- End position
uint32_t SHR(uint32_t x, int n)
{
    // Section 3.2
    return x >> n;
}

// Rotate right
uint32_t ROTR(uint32_t x, int n)
{
    // Section 3.2
    return (x >> n) | (x << (32 - n));
}

// Sig 0
uint32_t Sig0(uint32_t x)
{
    // Section 4.1.2
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

// Sig 1
uint32_t Sig1(uint32_t x)
{
    // Section 4.1.2
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

// sig 0
uint32_t sig0(uint32_t x)
{
    // Section 4.1.2
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

// sig 1
uint32_t sig1(uint32_t x)
{
    // Section 4.1.2
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

// uint64_t no_zeros_bytes(uint64_t no_bits)
// {
//     uint64_t result = 512 - (no_bits % 512ULL);

//     if (result < 65)
//     {
//         result += 512;
//     }

//     result -= 72;

//     return (result / 8ULL);
// }
#pragma endregion

#pragma region NEXT BLOCK
// nextblock -- next hashing block
// Read from infile, into M, keeping track of the number of bits it
// has currently read
int nextblock(union block *M, FILE *infile, uint64_t *nobits, enum flag *status)
{
    // check current status
    if (*status == FINISH)
        return 0; // this will break out of while in main

    // otherwise not on finish -- check status
    // if (*status == PAD1){
    //     // send block back that contains all 0s except for last 64 bits should be nobits in big endian integer

    //     M.eight[0] = 0x80; // set first byte set, last 7 unset

    //     // 56 --> First 8 bits set above
    //     for(int i =1; i<56; i++){
    //         M.eight[i] = 0; // Set all bits in unsigned integer to 0
    //     }
    //     M.sixfour[7] = *nobits; // set last byte
    //     // set status to finish
    //     *status = FINISH;
    //     return 1;
    // }

    // Need to check if it's a 0 block
    if (*status == PAD0)
    {
        for (int i = 0; i < 56; i++)
        {
            M->eight[i] = 0;
        }
        M->sixfour[7] = *nobits;
        *status = FINISH;
        return 1;
    }

    // assume nobits set to 0 -- start by default?
    size_t nobytesread = fread(M->eight, 1, 64, infile); // read into 8bit message block, 1byte, 64times, filehandler

    // Try to read 64 bytes from file
    if (nobytesread == 64)
    {
        return 1;
    }
    // check now if theres enough room left in block to do all padding
    // need 8 bytes for a 64 bit integer and a byte to stick 1 into.

    // if we can fit all padding in last block:
    if (nobytesread < 56)
    {
        M->eight[nobytesread] = 0x80; // will be position of where to put 1 bit in byte
        for (int i = nobytesread + 1; i < 56; i++)
        {
            M->eight[i] = 0;
        }
        M->sixfour[7] = *nobits;
        *status = FINISH;
        return 1;
    }

    // Otherwise have read at least 56(inclusive) bytes from file, but less than 64(exculsive) --> Need to padd with 0's
    M->eight[nobytesread] = 0x80;
    for (int i = nobytesread + 1; i < 64; i++)
    {
        M->eight[i] = 0;
    }
    *status = PAD0;
    return 1;

    // uint8_t i;

    // // MAIN ALGORITHM LOOP
    // // Try read file 1 byte at a time..
    // // Read into b (& -> Address)
    // // Read 1 byte, read 1 copy of bytes, from inFile
    // for (*nobits = 0, i = 0; fread(&M.eight[i], 1, 1, infile) == 1; *nobits += 8)
    // {
    //     printf("%02" PRIx8, &M.eight[i]);
    // }

    // printf("%02" PRIx8, 0x80); //Append Bits: 1000 0000

    // // PADDING TO BE DONE ON THE FLY
    // for (uint64_t i = (no_zeros_bytes(*nobits)); i > 0; i--)
    // {
    //     printf("%02" PRIx8, 0x00);
    // }

    // printf("%016" PRIx64 "\n", *nobits); // Length of original message
}
#pragma endregion

#pragma region NEXT HASH
// Taking a block M,
// calculating next block H
int nexthash(union block *M, uint32_t *H)
{
    // Section 6.2.2 -- Step 1/5
    // message schedule
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h; // become what current H is
    uint32_t T1, T2;

    // first half
    for (int t = 0; t < 16; t++)
    {
        W[t] = M->threetwo[t]; // deferencing the pointer
    }

    for (int t = 16; t < 64; t++)
    {
        sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16];
    }

    // Step 2/5
    a = H[0]; // Automatic deference of pointer
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // Step 3/5
    for (int t = 0; t < 64; t++)
    {
        T1 = h + Sig1(e) + Ch(e, f, g) + K[t] + W[t];
        T2 = Sig0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }
}
#pragma endregion

#pragma region MAIN
int main(int argc, char *argv[])
{
    // Expect command line arg
    if (argc != 2)
    {
        printf("Error: expected single filename as argument\n");
        return 1;
    }

    FILE *infile = fopen(argv[1], "rb");

    // Error handling -- Can't open file
    if (!infile)
    {
        printf("Error: couldn't open file %s. \n", argv[1]);
        return 1;
    }

    // Initial hash values -- Section 5.5.3
    uint32_t H[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

    // nextblock params
    union block M;
    uint64_t nobits = 0;
    enum flag status = READ;
    // Read through all of the padded message blocks.
    // When reading into the block -> Do in 8-bits
    while (nextblock(&M, infile, &nobits, &status))
    {
        // Calculate next Hash value of M, hash value of H
        // Passing as address
        // Using values in array --> Do in 32-bits
        nexthash(&M, H);
    }

    for (int i = 0; i < 8; i++)
    {
        printf("%02" PRIX32, H[i]);
        printf("\n");
    }

    fclose(infile);

    return 0;
}
#pragma endregion