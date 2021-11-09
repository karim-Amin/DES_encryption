/*
* File name : 1701009.cpp
* Description : this file will include the impelementation for DES security algorithm there will be two options to select to encrypt 
* any message and the key will be required to compelete the process ,the second one is to decrype the cipher text using specific key.
* Autho : Karim Mohamed Amin
* Date : 9/11/2021
*/

#include <iostream>
#include <string.h>
#include <map>
using namespace std;
/**********************************************************************
*                               Definitions                           *
***********************************************************************/
#define LEFT_KEY_PART_SIZE 28
#define XOR_GATE_OUTPUT_SIZE 48
/**********************************************************************
*                               Function Prototypes                   *
***********************************************************************/
string convertBinToHex(string bin);
string convertHexToBin(string hex);
string getPermuted(string input_text, int permute_table[], int table_size);
string leftCircularShift(string input_text,int num_shifts);
string xorGate(string input1, string input2);
string encrypt(string plain_text,string key);
int main()
{
 
    string plain_text = "7A6C731D22347676";
    string key = "1323445A6D788381";
    string bin_plain_text = convertHexToBin(plain_text);
    string bin_key = convertHexToBin(key);
    cout << encrypt(bin_plain_text, bin_key);
    return 0;
}
/**********************************************************************
*                               Function Definitions                  *
***********************************************************************/
/*
* Description : TO be able to represent the hexadecimal format
*/
string convertBinToHex(string bin) {
    /*this counter used to loop over the string*/
    int i;
    /*this will hold the format in hexa after finish conversion*/
    string hexa_format;
    map <string, string>conversion;
    conversion["0000"] = "0";
    conversion["0001"] = "1";
    conversion["0010"] = "2";
    conversion["0011"] = "3";
    conversion["0100"] = "4";
    conversion["0101"] = "5";
    conversion["0110"] = "6";
    conversion["0111"] = "7";
    conversion["1000"] = "8";
    conversion["1001"] = "9";
    conversion["1010"] = "A";
    conversion["1011"] = "B";
    conversion["1100"] = "C";
    conversion["1101"] = "D";
    conversion["1110"] = "E";
    conversion["1111"] = "F";
    for (i = 0; i < bin.size(); i+=4) {
        string buff = "";/*empty string to hold four bits in binary format*/
        for (int j = 0; j < 4; j++) {
            buff += bin[i + j];
        }
        hexa_format += conversion[buff];
    }
    return hexa_format;

}
/*
* Description : TO be able to represent the binary  format
*/
string convertHexToBin(string hex) {
    /*this counter used to loop over the string*/
    int i;
    /*this will hold the format in hexa after finish conversion*/
    string binary_format = "";
    map <char, string>conversion;
    conversion['0'] = "0000";
    conversion['1'] = "0001";
    conversion['2'] = "0010";
    conversion['3'] = "0011";
    conversion['4'] = "0100";
    conversion['5'] = "0101";
    conversion['6'] = "0110";
    conversion['7'] = "0111";
    conversion['8'] = "1000";
    conversion['9'] = "1001";
    conversion['A'] = "1010";
    conversion['B'] = "1011";
    conversion['C'] = "1100";
    conversion['D'] = "1101";
    conversion['E'] = "1110";
    conversion['F'] = "1111";
    for (i = 0; i < hex.size(); i++) {
        char buff ;/*empty string to hold one hexa bit in hex format*/
        buff = hex[i];
        binary_format += conversion[buff];
    }
    return binary_format;
}
/*
* Description : this function will apply the permutaion as required ,and it will take the input message in binary format
* finally it will return the text after permutaion in binary format
*/
string getPermuted(string input_text, int permute_table[], int size) {
    int i;
    string text_after_permutation = "";
    for (i = 0; i < size; i++) {
        int new_index = permute_table[i]-1;
        text_after_permutation += input_text[new_index];
    }
    /*convert the binary to hexa */
    return text_after_permutation;
}
/*
* Description : the main goal here is to shift the input text with specific number 
* it will take the input text in binary format,and return it in binary format
*/
string leftCircularShift(string input_text,int num_shifts) {
    int i  ;
    /*buffer to hold the shifted result*/
    string shifted_bits = "";
    /*this loop to make more than one shift*/
    for (i = 0; i < num_shifts; i++) {
        /*this loop to shift the bits one time to the left*/
        for (int j = 1; j < LEFT_KEY_PART_SIZE; j++) {
            shifted_bits += input_text[j];
        }
        /*then put this bit in the LSB*/
        shifted_bits += input_text[0];
        /*update the value in the input text*/
        input_text = shifted_bits;
        /*reset the shifted bits to continue shifting if required*/
        shifted_bits = "";
    }
    return input_text;
}
/*
* Description : this function will return the result of xor operation used in DES
*/
string xorGate(string input1, string input2) {
    /*counter to loop with*/
    int i;
    string result = "";
    for (i = 0; i < XOR_GATE_OUTPUT_SIZE; i++) {
        if (input1[i] == input2[i]) {
            result += '0';
        }
        else {
            result += '1';
        }
    }
    return result;
}
/*
* Description : this function do all premutations in DES ,also it generates all subkeys,and impelement all the sixteen rounds
* finally it will return the cipher text
*/
string encrypt(string plain_text,string key) {
    /*this array will hold the drived subkeys*/
    string keys[16];
    /*First generate subkeys from the key we have*/
    /*permutation choice 1 table*/
    int premuted_choice1_table[56] = { 57, 49, 41, 33, 25, 17, 9,
                   1, 58, 50, 42, 34, 26, 18,
                   10, 2, 59, 51, 43, 35, 27,
                   19, 11, 3, 60, 52, 44, 36,
                   63, 55, 47, 39, 31, 23, 15,
                   7, 62, 54, 46, 38, 30, 22,
                   14, 6, 61, 53, 45, 37, 29,
                   21, 13, 5, 28, 20, 12, 4 };
    /*circular shift left table*/
    int shift_table[16] = { 1, 1, 2, 2,
                            2, 2, 2, 2,
                            1, 2, 2, 2,
                            2, 2, 2, 1 };
    /*permutation choice 2 table*/
    int premuted_choice2_table[48] = { 14, 17, 11, 24, 1, 5,
                         3, 28, 15, 6, 21, 10,
                         23, 19, 12, 4, 26, 8,
                         16, 7, 27, 20, 13, 2,
                         41, 52, 31, 37, 47, 55,
                         30, 40, 51, 45, 33, 48,
                         44, 49, 39, 56, 34, 53,
                         46, 42, 50, 36, 29, 32 };
    /*apply premutation choice 1 this key will be 56 bits*/
    string compresed_key = getPermuted(key, premuted_choice1_table, 56);
    /*split the key into two halves */
    string left_half = compresed_key.substr(0,28);
    string right_half = compresed_key.substr(28, 28);
    /*apply left circular shift using the table above each key will be 56 bits*/
    string shifted_keys[16];
    for (int i = 0; i < 16; i++) {
        /*after applying the left circular shift ,i merged the two halves still the key size is 56 bits*/
        shifted_keys[i] = leftCircularShift(left_half, shift_table[i]) + leftCircularShift(right_half, shift_table[i]);
    }
    /*apply premutation choice 2 this key will be 48 bits*/
    string subkeys[16];
    for (int i = 0; i < 16; i++) {
        subkeys[i] = getPermuted(shifted_keys[i], premuted_choice2_table,48);
    }
    /*now we have all subkeys we can use them in encryption*/
    /* Initial Permutation Table*/
    int initial_permutation_table[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
                                          60, 52, 44, 36, 28, 20, 12, 4,
                                          62, 54, 46, 38, 30, 22, 14, 6,
                                          64, 56, 48, 40, 32, 24, 16, 8,
                                          57, 49, 41, 33, 25, 17, 9, 1,
                                          59, 51, 43, 35, 27, 19, 11, 3,
                                          61, 53, 45, 37, 29, 21, 13, 5,
                                          63, 55, 47, 39, 31, 23, 15, 7 };
    string permutated_plain_text = getPermuted(plain_text, initial_permutation_table, 64);
    /*now to follow the DES standard we have to split plain text into two halves*/
    string plain_left_half = permutated_plain_text.substr(0, 32);
    string plain_right_half = permutated_plain_text.substr(32, 32);
    /* expension permutation table*/
    /*this table will expand our plain text from 32 bits into 48 bits*/
    int expansion_permutation_table[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
                                            6, 7, 8, 9, 8, 9, 10, 11,
                                           12, 13, 12, 13, 14, 15, 16, 17,
                                           16, 17, 18, 19, 20, 21, 20, 21,
                                           22, 23, 24, 25, 24, 25, 26, 27,
                                           28, 29, 28, 29, 30, 31, 32, 1 };


    return "";
}