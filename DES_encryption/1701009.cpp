/*
* File name : 1701009.cpp
* Description : this file will include the impelementation for DES security algorithm there will be two options to select to encrypt 
* any message and the key will be required to compelete the process ,the second one is to decrype the cipher text using specific key.
* Autho : Karim Mohamed Amin
* Date : 9/11/2021
*/

#include <iostream>
#include <string>
#include <map>
using namespace std;
/**********************************************************************
*                               Definitions                           *
***********************************************************************/
#define LEFT_KEY_PART_SIZE 28
#define DES_NUM_OF_STAGES 16
/**********************************************************************
*                               Function Prototypes                   *
***********************************************************************/
string convertBinToHex(string bin);
string convertHexToBin(string hex);
string getPermuted(string input_text, int permute_table[], int table_size);
string leftCircularShift(string input_text,int num_shifts);
string xorGate(string input1, string input2);
string encrypt(string plain_text,string key);
string substitutionPermuted(string input_text,int sub_table[8][4][16],int num_tables,int num_rows,int num_colmuns);
string adjustFourBits(int number);
void swapStr(string str1, string str2);
int binaryToDecimal(int n);
int main()
{
 
    string plain_text = "7A6C731D22347676";
    string key = "1323445A6D788381";
    string bin_plain_text = convertHexToBin(plain_text);
    string bin_key = convertHexToBin(key);
    string cipher = encrypt(bin_plain_text, bin_key);
    cipher = convertBinToHex(cipher);
    cout <<"the cipher text : " <<cipher<<endl ;
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
* Description : this function will apply the permutaion as required 
*,and it will take the input message in binary format
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
    for (i = 0; i < input1.size(); i++) {
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
* Description : this function do all premutations in DES 
* also it generates all subkeys,and impelement all the sixteen rounds
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
    string shifted_keys[DES_NUM_OF_STAGES];
    for (int i = 0; i < DES_NUM_OF_STAGES; i++) {
        /*after applying the left circular shift ,i merged the two halves still the key size is 56 bits*/
        shifted_keys[i] = leftCircularShift(left_half, shift_table[i]) + leftCircularShift(right_half, shift_table[i]);
    }
    /*apply premutation choice 2 this key will be 48 bits*/
    string subkeys[DES_NUM_OF_STAGES];
    for (int i = 0; i < DES_NUM_OF_STAGES; i++) {
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
    /* expension permutation table*/
  /*this table will expand our plain text from 32 bits into 48 bits*/
    int expansion_permutation_table[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
                                            6, 7, 8, 9, 8, 9, 10, 11,
                                           12, 13, 12, 13, 14, 15, 16, 17,
                                           16, 17, 18, 19, 20, 21, 20, 21,
                                           22, 23, 24, 25, 24, 25, 26, 27,
                                           28, 29, 28, 29, 30, 31, 32, 1 };
    /*substitution box table each six bits will be compersed into 4 bits based on table */
    /*we have 8 tables with 4 rows and 16 columns*/
    int substitution_table[8][4][16] = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                          0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                          4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },

                        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                          3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                          0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },

                        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                          13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                          13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                          1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },

                        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                          13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                          10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                          3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },

                        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                          14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                          4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                          11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },

                        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                          10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                          9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                          4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },

                        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                          13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                          1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                          6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },

                        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                          1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                          7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                          2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
    /* permutaion table*/ 
    int permutaion_table[32] = {16, 7, 20, 21,
                                29, 12, 28, 17,
                                1, 15, 23, 26,
                                5, 18, 31, 10,
                                2, 8, 24, 14,
                                32, 27, 3, 9,
                                19, 13, 30, 6,
                                22, 11, 4, 25 };
    /*inverse initial permutation*/
    int inverse_init_perm_table[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
                           39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30,
                           37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28,
                           35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26,
                           33, 1, 41, 9, 49, 17, 57, 25 };
    string permutated_plain_text = getPermuted(plain_text, initial_permutation_table, 64);
    /*now to follow the DES standard we have to split plain text into two halves*/
    string plain_left_half = permutated_plain_text.substr(0, 32);
    string plain_right_half = permutated_plain_text.substr(32, 32);
    /*holds expanded plain text left half*/
    string expanded_right_plain;
    /*holds the result from the xor operation*/
    string xor_result;
    /*to hold the substitution result*/
    string substituation_result;
    /*to hold the final permutation in the round*/
    string final_permutation;
    /*this loop for 16 rounds*/
    /*this is the impelementation for only one round*/
    for (int i = 0; i < DES_NUM_OF_STAGES; i++) {
        /*expanding the plain text left half which will be 48 bits */
        expanded_right_plain = getPermuted(plain_right_half, expansion_permutation_table, 48);
        /*the first xor operation in the round*/
        xor_result = xorGate(expanded_right_plain, subkeys[i]);
        /*the size of this plain text will be 32 bits again */
        substituation_result = substitutionPermuted(xor_result, substitution_table, 8, 4, 16);
        /*last permutation stage*/
        final_permutation = getPermuted(substituation_result, permutaion_table, 32);
        /*the second xor operation in the round*/
        plain_right_half = xorGate(final_permutation, plain_left_half);
        /*swap the right half plain text and the left half plain text */
        cout << "the right palin half at round " << i + 1 << " is : " << convertBinToHex(plain_right_half) << endl;
        cout << "the left palin half at round " << i + 1 << " is : " << convertBinToHex(plain_left_half) << endl;
        swapStr(plain_right_half, plain_left_half);
    }
    /*32 bits final swap */
    swapStr(plain_right_half, plain_left_half);
    /*combine the two halves*/
    string combined = plain_left_half + plain_right_half;
    /*final inverse permutation*/
    string cipher = getPermuted(combined, inverse_init_perm_table, 64);
    return cipher;
}
/*
 * Description : this function receives the input_text which is 48 bits and devide them into 8 groups each group is six bits
 * then substitute in the tables ,and permute each group to 4 bits only so we will get 32 bits plain text
 */
string substitutionPermuted(string input_text, int sub_table[8][4][16], int num_tables, int num_rows, int num_colmuns) {
    /*this will hold our text after permutation*/
    string text_after_permutation = "";
    /*this holds the four bits remaining*/
    int new_four_bits;
    /*loop counter*/
    int i;
    /*counter will split the text into 8 groups consist of 6 bits*/
    int split_count;
    /*holds the six bits in 48 bits*/
    string six_bits = "";
    string row_num ;
    string column_num;
    /*loop across all the groups*/
    for (i = 0; i < num_tables; i++) {
        /*this takes six bits each iteration*/
        split_count = i * 6;
        six_bits = input_text.substr(split_count,6);
        /*the row number will be the first and last bits*/
        row_num = six_bits.substr(0,1)+ six_bits.substr(5,1);
        /*the column number will be the four middel bits*/
        column_num = six_bits.substr(1,4);
        /*convert the string and the binary into decimal value to access the sub table*/
        int int_row_num = binaryToDecimal(stoi(row_num));
        int int_column_num = binaryToDecimal(stoi(column_num));
        /*accessing the sub table and get the new index*/
        new_four_bits = sub_table[i][int_row_num][int_column_num];
        text_after_permutation += adjustFourBits(new_four_bits);
    }
    return text_after_permutation;
}
/*
 * Description : converts the decimal number to its corresponding binary code in string format
 */
string adjustFourBits(int number) {
    switch (number) {
    case 0: return "0000";
    case 1: return "0001";
    case 2: return "0010";
    case 3: return "0011";
    case 4: return "0100";
    case 5: return "0101";
    case 6: return "0110";
    case 7: return "0111";
    case 8: return "1000";
    case 9: return "1001";
    case 10: return "1010";
    case 11: return "1011";
    case 12: return "1100";
    case 13: return "1101";
    case 14: return "1110";
    case 15: return "1111";
    default: return "XXXX";
    }
}
/* 
 * Description : to convert the binary code to decimal value   
 */
int binaryToDecimal(int n)
{
    int num = n;
    int dec_value = 0;

    // Initializing base value to 1, i.e 2^0
    int base = 1;

    int temp = num;
    while (temp) {
        int last_digit = temp % 10;
        temp = temp / 10;

        dec_value += last_digit * base;

        base = base * 2;
    }

    return dec_value;
}
/*
* Description : to swap two strings 
*/
void swapStr(string str1, string str2) {
    string temp = str1;
    str1 = str2;
    str2 = temp;
}