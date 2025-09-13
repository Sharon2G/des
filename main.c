#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Substitution table (ftable) used in encryption/decryption
uint8_t ftable [] = {
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46 };


// Key scheduling function: rotates key and extracts 8-bit subkeys
uint8_t K(uint64_t *key, int x) {
    *key = (*key << 1) | (*key >> 63);
    uint8_t result = (*key >> ((x % 8) * 8)) & 0xFF;

    return result;
}

// Key scheduling function for decryption (reverse of K)
uint8_t DK(uint64_t *key, int x) {
    uint8_t result = (*key >> ((x % 8) * 8)) & 0xFF;
    *key = (*key >> 1) | (*key << 63);

    return result;
}

// The G function applies a series of substitutions using ftable and subkeys
uint16_t G(uint16_t w, int round, uint8_t* keys) {

    uint8_t g1 = w >> 8;
    uint8_t g2 = w & 0xFF;

    uint8_t g3 = ftable[g2 ^ keys[0]] ^ g1;
    uint8_t g4 = ftable[g3 ^ keys[1]] ^ g2;
    uint8_t g5 = ftable[g4 ^ keys[2]] ^ g3;
    uint8_t g6 = ftable[g5 ^ keys[3]] ^ g4;
    return (g5 << 8) | g6;
}

// Function to encrypt or decrypt a block
void encryptFile(uint64_t *block, uint64_t key, int toEncrypt) {

    // Extract 16-bit words from 64-bit block
    uint16_t W0 = (*block >> 48) & 0xFFFF;
    uint16_t W1 = (*block >> 32) & 0xFFFF;
    uint16_t W2 = (*block >> 16) & 0xFFFF;
    uint16_t W3 = (*block) & 0xFFFF;

    // Extract 16-bit subkeys from 64-bit key
    uint16_t K0 = (key >> 48) & 0xFFFF;
    uint16_t K1 = (key >> 32) & 0xFFFF;
    uint16_t K2 = (key >> 16) & 0xFFFF;
    uint16_t K3 = (key) & 0xFFFF;

    // Input whitening
    uint16_t R0 = W0 ^ K0;
    uint16_t R1 = W1 ^ K1;
    uint16_t R2 = W2 ^ K2;
    uint16_t R3 = W3 ^ K3;

    uint16_t F0, F1, oldR2, oldR3;

    if (toEncrypt) { // 16 rounds of encryption
        for (int round = 0; round < 16; round++) {
            uint8_t GK1, GK2, GK3, GK4, GK5, GK6, GK7, GK8, K9, K10, K11, K12;
            uint8_t *subkeys, *subkeys1;

            // Generate the 12 subkeys
            GK1 = K(&key, 4 * round);
            GK2 = K(&key, 4 * round + 1);
            GK3 = K(&key, 4 * round + 2);
            GK4 = K(&key, 4 * round + 3);
            GK5 = K(&key, 4 * round);
            GK6 = K(&key, 4 * round + 1);
            GK7 = K(&key, 4 * round + 2);
            GK8 = K(&key, 4 * round + 3);
            K9 = K(&key, 4 * round);
            K10 = K(&key, 4 * round + 1);
            K11 = K(&key, 4 * round + 2);
            K12 = K(&key, 4 * round + 3);
            
            uint8_t temp[4] = {GK1, GK2, GK3, GK4};
            subkeys = temp;
            uint8_t temp1[4] = {GK5, GK6, GK7, GK8};
            subkeys1 = temp1;

            // Function F()
            uint16_t T0 = G(R0, round, subkeys);
            uint16_t T1 = G(R1, round, subkeys1);
            F0 = (T0 + 2 * T1 + (( K9 << 8 ) | K10)) % 65536;
            F1 = (2 * T0 + T1 + (( K11 << 8 ) | K12)) % 65536;  
            
            uint16_t newR0, newR1;
            newR0 = ((R2 ^ F0) >> 1) | ((R2 ^ F0) << 15);
            newR1 = ((R3 << 1)|(R3 >> 15)) ^ F1;
            
            
            oldR2 = R2;
            oldR3 = R3;

            R2 = R0;
            R3 = R1;
            R0 = newR0;
            R1 = newR1;
        }
    }

    else { // 16 rounds of decryption
        for (int round = 15; round >= 0; round--) {
            uint8_t GK1, GK2, GK3, GK4, GK5, GK6, GK7, GK8, K9, K10, K11, K12;
            uint8_t *subkeys, *subkeys1;

            // Generate the 12 subkeys
            K12 = DK(&key, 4 * round + 3);
            K11 = DK(&key, 4 * round + 2);
            K10 = DK(&key, 4 * round + 1);
            K9  = DK(&key, 4 * round);
            GK8 = DK(&key, 4 * round + 3);
            GK7 = DK(&key, 4 * round + 2);
            GK6 = DK(&key, 4 * round + 1);
            GK5 = DK(&key, 4 * round);
            GK4 = DK(&key, 4 * round + 3);
            GK3 = DK(&key, 4 * round + 2);
            GK2 = DK(&key, 4 * round + 1);
            GK1 = DK(&key, 4 * round);

            uint8_t temp[4] = {GK1, GK2, GK3, GK4};
            subkeys = temp;
            uint8_t temp1[4] = {GK5, GK6, GK7, GK8};
            subkeys1 = temp1;

            // Function F()
            uint16_t T0 = G(R0, round, subkeys);
            uint16_t T1 = G(R1, round, subkeys1);

            F0 = (T0 + 2 * T1 + (( K9 << 8 ) | K10)) % 65536;
            F1 = (2 * T0 + T1 + (( K11 << 8 ) | K12)) % 65536;                

            uint16_t newR0, newR1;

            newR0 = ((R2 << 1)|(R2 >> 15)) ^ F0;
            newR1 = ((R3 ^ F1) >> 1)|((R3 ^ F1) << 15);
            
            oldR2 = R2;
            oldR3 = R3;

            R2 = R0;
            R3 = R1;
            R0 = newR0;
            R1 = newR1;
        }
    }

    //Last swap
    uint16_t y0 = R2;
    uint16_t y1 = R3;
    uint16_t y2 = R0;
    uint16_t y3 = R1;  

    // Output whitening
    uint16_t C0 = y0 ^ K0;
    uint16_t C1 = y1 ^ K1;
    uint16_t C2 = y2 ^ K2;
    uint16_t C3 = y3 ^ K3;

    *block = ((uint64_t)C0 << 48) | ((uint64_t)C1 << 32) | ((uint64_t)C2 << 16) | C3;

}

int main(int argc, char *argv[]) {
    if (argc != 8) {
        perror("Incorrect input");
        return 1;
    }

    int toEncrypt = 0;
    FILE *keyFile, *inputFile, *outputFile;
    int inputFd;

    // Parse command-line arguments
    for (int ii = 1; ii < argc; ii++) {
        if (strcmp(argv[ii], "-e") == 0) {
            toEncrypt = 1;
        } 
        else if (strcmp(argv[ii], "-k") == 0) {
            ii++;
            keyFile = fopen (argv[ii], "r");
        } 
        else if (strcmp(argv[ii], "-in") == 0) {
            ii++;
            inputFd = open(argv[ii], O_RDONLY); 
            inputFile = fopen (argv[ii], "r");
        }   
        else if (strcmp(argv[ii], "-out") == 0) {
            ii++;
            outputFile = fopen (argv[ii], "w");
        } 
    }

    uint64_t key;

    fscanf(keyFile, "%llx", &key);

    // Process file in 64-bit blocks
    if (toEncrypt) { // Encrypt
        while (1) {
            uint64_t block = 0;
            char buffer[8];
            int bytesRead = read(inputFd, buffer, sizeof(buffer));
            if (bytesRead == 0)
                break;
            else if (bytesRead < 8) {
                // Add 0 padding
                memset(buffer + bytesRead, 0, 8 - bytesRead);
                for (int ii = 0; ii < 8; ii++) {
                    block |= (uint64_t)buffer[ii] << (56 - ii * 8);
                }

            }
            else {
                for (int ii = 0; ii < 8; ii++) {
                    block |= (uint64_t)buffer[ii] << (56 - ii * 8);
                }
            }
            encryptFile(&block, key, toEncrypt);
            fprintf(outputFile, "%llx\n", block);
        }
    }

    else { //Decrypt
        uint64_t block = 0;
        while (fscanf(inputFile, "%llx", &block) != EOF) {
            encryptFile(&block, key, toEncrypt);

            unsigned char bytes[8];
            for (int ii = 0; ii < 8; ii++) {
                bytes[ii] = (block >> (56 - ii * 8)) & 0xFF;
                if (bytes[ii] != 0)
                    fprintf(outputFile, "%c", bytes[ii]);
            }
        }
    }

    fclose(keyFile);
    fclose(inputFile);
    close(inputFd);
    fclose(outputFile);

    return 0;
}