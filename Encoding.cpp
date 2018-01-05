/*
 * Copyright Jonathan Booher 2016 All Rights Reserved
 */
#include "Encoding.h"
#include "filelib.h"
#include <cmath>

// I have this set as a constant so that a password would not have to be remembered when grading.
//   The transition to a user entered password wouldd be trivial.
uint8_t encryptionKey[16] = {
  'Q' , 'u' , 'O' , 'k' , 'A' , 's' , ' ' , 'R' , 'u' , 'L' , 'e' , '2' , '0' ,'1' , '7' , '!'
};

/*
 * Init the initial dictionary for the input.
 * We put each character in the istream imput into the map dictionary with the value
 * being an integer that starts from 1 and goes upt to the number of unique characters in the
 * input.
 */
void initDictionary(Map<string , int> &dictionary , istream &input){
    string t(1,EOF) ;
    dictionary.add(t , 0);
    int number = 1 ;
    do{
        int character = input.get() ;
        if(character==EOF) break ;

        string temp(1,(char)character) ;
        if(!dictionary.containsKey(temp)){
            dictionary[temp] = number ;
            number++ ;
        }

    }while(true) ;
}

/*
 * This function will encode the data from the istream input into the vector<bool> &output
 * using the information in the dictionary map.
 *
 * for all intents and purposes the vector<bool> can be seen as an obitstream but allows for
 * subsequent itteration through the values.
 */
void encode(istream &input , vector<bool>&output , Map<string , int> dictionary){
    string readIn="" ;
    int currNumBits = ceil(log2(dictionary.size())) ; // the number of bits that is needed to cover the number of cahracters in the map.
    int character ; // have this outside so that I can use it in the while loop control.

    do{
        character = input.get() ; // use get so that I do not skip spaces.

        if(!dictionary.containsKey(readIn+(char)character)){ // the dictionary ddoes not recognize the concatenation.
            for(int y = currNumBits-1 ; y >=0 ; y--){ //  wrte the bits representing the number in the dictonary for the given string to the output
                if((dictionary[readIn] >> y)&0x1 == 0x1){
                    output.push_back(1);
                }else{
                    output.push_back(0);
                }
            }
            if(dictionary.size() > pow(2,currNumBits)-1){ // we need more bits to represent the next entry inthe dictionary.
                currNumBits++ ;
            }
            dictionary.add(readIn+(char)character,dictionary.size()); // add the concatenation to the dictionary.
            readIn = "" ; // reset the data read in
        }
        readIn+=character ; // add the read in character
    }while(character!=-1) ; // character == -1 meanss we are at the end of the input.

    for(int f = currNumBits-1 ; f >=0 ; f--){ // this puts the EOF code at the end.
        output.push_back(0);
    }
}

/*
 * This fucntion will compress and then encrypt the data in input and wirte that out to output.
 */
void compress(istream& input, obitstream& output) {

    Map<string , int> dictionary ;
    initDictionary(dictionary , input); // create the initial dictionary.
    rewindStream(input) ;

    vector<bool> outputBits ;
    string a = dictionary.toString() ;

    for(int x = 0 ; x< a.length() ; x++){ // write the bits representing the dictionary to the outputBits vector
        for(int y = 7 ; y>=0 ; y--){
            if((a[x] >> y)&0x1 ==0x1) outputBits.push_back(1);
            else outputBits.push_back(0);
        }
    }

    encode(input , outputBits , dictionary); // add to the end of the putputBits vector the binary represenation of the compressed data.

    int residue = outputBits.size()%8 ; // if the compressed data is not an even multiple of 8, we cannot represent it fully in uint8_t s so add 0s to the end
    if(outputBits.size()%8!=0){
        for(int x = 0 ; x< 8-residue ; x++){
            outputBits.push_back(0); ;
        }
    }

    uint8_t *toEncrypt = new uint8_t[outputBits.size()/8] ; // init with the correct size

    for(int x =0 ; x< outputBits.size() ; x+=8){ // fill the uint8_t array with the correct vallues to represent the compressed data
        uint8_t tmp = 0 ;
        for(int y = 7 ; y>=0 ; y--){
            tmp+=pow(2,y)*outputBits[x+7-y] ; // simple binary to integer convereter
        }
        toEncrypt[x/8] = tmp ;
    }

    int toEncLen = outputBits.size()/8 ; // temp varaible to make the next calulation easier.
    int roundedLength = toEncLen ;
    roundedLength+= (toEncLen%16==0) ? 0 : 16-(toEncLen%16) ; // if the data is not an even multiple of 16 bytes, we make rounded leangth the next multiple of 16bytes.

    uint8_t *encrypted = new uint8_t[roundedLength] ; // init.
    memset(encrypted , 0 , roundedLength) ; // set to 0 all elements.

    AES encoder(encryptionKey) ;

    uint8_t *encSave = toEncrypt ;
    encoder.encryptBuffer(encSave , encrypted , toEncLen); // encrypt the data.

    for(int x = 0 ; x< roundedLength ; x++){ // simple integer to binary converter to write out the bits for the encrypted integers to the obitstream output.
        for(int y = 7 ; y >=0 ; y--){
            if((encrypted[x] >> y)&0x1 ==0x1) output.writeBit(1);
            else output.writeBit(0) ;
        }
    }
    delete[] toEncrypt ; // cleanup
    delete[] encrypted ;
}

/*
 * This fucntion wil decode the bits iin input into the ostream output according to the map dictionary.
 */
void decode(vector<bool>&input , ostream &output , Map<int , string> dictionary ){
    int currNumBits = ceil(log2(dictionary.size())) ; // minimum number of bits needed to represent all the nubmers in the dictionary.
    int keyOne = 0 ;
    int index =0;

    for(int x = currNumBits ; x>=1  ; x--){ // init key one to the integer value of the first 8bits in the input
        int bit = input[index] ;
        index++ ;
        if(bit==-1|| index > input.size()) break ;
        keyOne+=bit*pow(2,x-1) ;
    }

    string one = dictionary[keyOne] ; // get the value for the input.
    string two ;
    do{
        bool flag = false ; // used to signal the end of the input.

        int keyTwo = 0 ;
        for(int x = currNumBits ; x>=1  ; x--){ // convert the first currNumBits to its integer value.

            int bit = input[index] ;
            index++ ;
            if(bit==-1 || index > input.size()){ // this is the end of the input.
                flag =true ;
                break ;
            }

            keyTwo+=bit*pow(2,x-1) ;
        }

        if(keyTwo == 0 || flag){ // this is the end of the encoded data
            output <<  one ;
            break ;
        }

        string val ;
        if(!dictionary.containsKey(keyTwo)){ // if the dictionary does not contain the current value, then the current value to be added is the concatenation of the previous value and itself
            flag = true ;
            val=one+one[0] ;
        }else{ // dictionary contains value so the current value to be added is the concatenation of the previous value and the current value.
            two = dictionary[keyTwo] ;
            val = one+dictionary[keyTwo][0] ;
        }

        output << one ; // write to output.

        dictionary.add(dictionary.size() , val) ; // add the apropriate value to the input.

        if(dictionary.size()-1 >= pow(2,currNumBits)-1) currNumBits++ ; // we need to increase the number of bits used to represent a key.

        if(flag) one = dictionary[dictionary.size()-1] ; // set the previous value to thee corret value depending on the previous if statements.
        else one = two ;

    }while(true) ;
}

/*
 * Decrypts and then decompresses the data in the ibitstream input into the ostream output.
 */
void decompress(ibitstream& input, ostream& output) {
    Map<string , int> temp ; // this will hold the dictionary.

    vector<bool> bitBuff ; // this will hold the bits of the input.

    while(true){ // rad and insert all the bits into the vector.
        int bit = input.readBit() ;
        if(bit==-1) break ;
        bitBuff.push_back(bit);
    }

    uint8_t *toDecrypt = new uint8_t[bitBuff.size()/8] ; // allocate approapriate size.

    for(int x =0 ; x< bitBuff.size() ; x+=8){ // convert the bits to their integer representations.
        uint8_t tmp = 0 ;
        for(int y = 7 ; y>=0 ; y--){
            tmp+=pow(2,y)*bitBuff[x+7-y] ;
        }
        toDecrypt[x/8] = tmp ;
    }
    AES decryptor(encryptionKey) ;

    uint8_t *decrypted = new uint8_t[bitBuff.size()/8] ; // allocate correct size.
    memset(decrypted , 0 , bitBuff.size()/8) ; // set to 0 .

    decryptor.decryptBuffer(toDecrypt , decrypted , bitBuff.size()/8); // cecrpyt the data.

    // the following is a little kludgy. But it works
    stringstream a ;
    for(int x = 0 ; x< bitBuff.size()/8 ; x++){ // add the char represenations of the decrypted integers to a stringstream
        a<<decrypted[x] ;
    }

    stringstream dictString ;

    bool flag = false ;
    char prev = '\0' ;
    while(a){ // uses this to isolate the characters that will comprise the dictionary into a seperate stringstream
        char t ;
        a>>std::noskipws >>t ; // use noskipws to handle spaces.
        if(!flag) dictString<<t ;

        if(t == '}' && prev!='"') break ; // condition for the end of the dictionary.

        prev =t ;
    }

    dictString>>temp ; // init the dictionary.

    vector<bool> buf ; // convert the uint8_t s from the decrypted buffer back to their bits for the decode function to handle.
    while(a){
        char chara ;
        a>>chara ;
        for(int y = 7 ; y>=0 ; y--){
            if((chara >> y)&0x1 ==0x1) buf.push_back(1);
            else buf.push_back(0);
        }
    }

    Map<int , string> dictionary ; // swap the key value pairs of the map.
    for(string str : temp.keys()){
        dictionary.add(temp[str] , str);
    }

    decode(buf , output , dictionary) ; // decodde the compressed bits in buff to output using the dictionary.

    delete[] toDecrypt ; // cleanup.
    delete[] decrypted ;
}
