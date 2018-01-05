/*
 * Copyright Jonathan Booher 2016 All Rights Reserved
 */

#include "aes.h"

// Constructor. Init the key to the value passed to the constructor
//   then expand the key into the key schedule.
AES::AES(uint8_t *k){
    Key=k ;
    KeyExpansion();
}

// abides by the AES statndard for expanding the key into the full key schedule
//   since we are doing AES 128, the key schedule has 44 words of 32 bytes.
void AES::KeyExpansion(){
    uint8_t tempa[4]; // Used to store previous

    memcpy(RoundKey , Key , 16) ; // first key in the schedule is just the Key itself

    // All other round keys are found from the previous round keys.
    for(int i=4; (i < (Nb * (10 + 1))); ++i){

        memcpy(tempa , RoundKey+((i-1)*4),4) ;

        if (i % Nk == 0){ // i%Nk==0 means this is the first word of this set of 4 words

            // rotational shift to the left combined with byte substitution and
            //   adding the round key for this round (Rcon).
            uint8_t k = sbox[tempa[0]];
            tempa[0]  = sbox[tempa[1]]^Rcon[i/Nk];
            tempa[1]  = sbox[tempa[2]];
            tempa[2]  = sbox[tempa[3]];
            tempa[3]  = k;
        }
        // set the four words of this to their appropriate values.
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
    }
}

// Adds the corresponding round key (from the RoundKey matrix) to the state array
// NOTE: Addition in AES is done in GF(256) so use XOR instead of +
void AES::AddRoundKey(uint8_t round){
    uint8_t i,j;
    for(i=0;i<4;++i){
        for(j = 0; j < 4; ++j){
            (*state)[i][j] ^= RoundKey[16*round + 4*i + j];
        }
    }
}

// Substitutes each byte of the state with a byte from the lookup table
// uses  sbox (for encrypting) if enc is true
// uses rsbox (for decrypting) if enc is false
void AES::SubBytes(bool enc){
    uint8_t i, j;
    for(i = 0; i < 4; ++i){
        for(j = 0; j < 4; ++j){
            if(enc) (*state)[j][i] = sbox [(*state)[j][i]];
            else    (*state)[j][i] = rsbox[(*state)[j][i]];
        }
    }
}

// performs a roational shift of rows 1 through 3 of the state matrix
// rotates each row x times where x is the row index.
// if enc is true, we are encrypting and need to shift left
// if enc is false, we are decrypting and need to shift right
void AES::ShiftRows(bool enc){
    uint8_t temp;
    int shift = (enc) ? 1 : -1 ;
    int begin = (enc) ? 0 :  3 ;

    for(int x = 1 ; x< 4 ; x++){
        for(int y = 0 ; y<x ; y++){
            temp = (*state)[begin][x] ;
            (*state)[begin        ][x] = (*state)[begin+shift  ][x];
            (*state)[begin+shift  ][x] = (*state)[begin+2*shift][x];
            (*state)[begin+2*shift][x] = (*state)[begin+3*shift][x];
            (*state)[begin+3*shift][x] = temp;
        }
    }
}

// multiplies two numbers together in GF(256)
// uses a modified version of the peasantAlgorithm
uint8_t peasantMultiply(uint8_t a , uint8_t b){
    uint8_t p = 0 ;

    for(int x = 0 ; x<8 ; x++){ // execute once for each bit
        if((b&0x1)==0x1){ // check if rightmost bit of b is set.
            p^=a ;
        }
        b >>=1 ;
        bool carry = false ;
        if((a>>7)==0x1){ // check if leftmost bit of a is set.
            carry = true ;
        }
        a <<=1 ;
        if(carry){
            a^=0x1b ; // XOR with the irreducible polynomial.
        }
    }
    return p ;
}

// Performs matrix multiplication of the matrix  cbox and the state if we are encrypting
// Performs matrix multiplication of the matrix rcbox and the state if we are decrypting
// NOTE: all math in AES is in GF(256) so the function peasantMultiply (see above) is used instead of *
//    and XOR is used instead of +
void AES::MixColumns(bool enc){
    uint8_t stateCp[4][4] ;
    memset(stateCp, 0 , sizeof(stateCp)) ;

    for(int x = 0 ; x<4 ; x++){
        for(int y = 0 ; y<4 ; y++){
            uint8_t res =0;
            for(int z = 0 ; z<4 ; z++){
                if(enc) res ^= peasantMultiply(cbox[y][z] , (*state)[x][z]) ;
                else res ^= peasantMultiply(rcbox[y][z] , (*state)[x][z]) ;
            }
            stateCp[x][y] = res ;
        }
    }
    memcpy(*state , stateCp , sizeof(stateCp)) ;
}

// This is the actual function that does the encrypting.
//   Follows the AES 128 standard and executes all the steps a total of 10 times
//   Uses the state private variable of the class to store the 128bits being encrypted/decrypted
//   if enc is true, we are encrypting else were are decrypting.
void AES::Cipher(bool enc){
    uint8_t round = 0;

    if(enc) AddRoundKey(0);
    else AddRoundKey(NumRounds);

    if(enc){
        for(round = 1; round < NumRounds; round++){
            SubBytes(enc);
            ShiftRows(enc);
            MixColumns(enc);
            AddRoundKey(round);
        }
        SubBytes(enc);
        ShiftRows(enc);
        AddRoundKey(NumRounds);
    }else{
        for(round=NumRounds-1;round>0;round--){
            ShiftRows(false);
            SubBytes(false);
            AddRoundKey(round);
            MixColumns(false);
        }
        ShiftRows(false);
        SubBytes(false);
        AddRoundKey(0);
    }
}

// encrypt a buffer (input) of arbitrary length (size) and put it into output
//   note that the output will always be a multiple of 16. Padding is added at the end so tthat
void AES::encryptBuffer(uint8_t*input , uint8_t*output , const uint32_t size){
    int numTimes = floor(size/16) ;
    int remaind = size%16 ;
    if(remaind) numTimes++ ;

    uint8_t encoded[16] , buff[16] ;
    int resultIndex=0 ;

    for(int x=0 ; x < numTimes ; x++){
        memset(buff , 0 , 16) ;

        int sizeToCpy = (remaind && x==numTimes-1) ? remaind : 16 ;
        memcpy(buff , input , sizeToCpy) ;

        encrypt(buff , encoded);

        memcpy(output+resultIndex , encoded , 16) ;

        resultIndex+=16 ;
        input+=16 ;
    }
}

// decrypt a buffer (input) of arbitrary length (size) and put it into output
//   note that the size of the input will always be a round multiple of 16
//   the output will be the same length as size.
void AES::decryptBuffer(uint8_t*input , uint8_t*output , const uint32_t size){
    int numTimes = floor(size/16);
    int remain = size%16 ;
    if(remain) numTimes++ ;

    uint8_t decoded[16] , buff[16] ;
    int resultIndex=0 ;

    int x = 0 ;
    for(x=0 ; x < numTimes ; x++){
        memcpy(buff , input , 16) ;

        decrypt(buff , decoded);

        int sizeToCpy = (remain && x ==numTimes-1) ? remain : 16 ;
        memcpy(output+resultIndex , decoded , sizeToCpy) ;

        resultIndex+=16 ;
        input+=16 ;
    }
}
// function to encrypt the 128 bits (16 uint8_t s) from input and put result into output.
void AES::encrypt(const uint8_t* input, uint8_t* output ){
    memcpy(output , input , 16) ; // do not alter the input.

    state = (state_t*)output;
    Cipher(true);
}

// function to decrypt the 128 bits (16 uint8_t s) from input and put result into output.
void AES::decrypt(const uint8_t* input, uint8_t *output){

    memcpy(output , input , 16) ; // do not alter the input
    state = (state_t*)output;

    Cipher(false) ;
}
