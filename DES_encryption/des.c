/**************************************************************************************************************
* File name : des.c
*
* Description : this file will include the impelementation for DES security algorithm.
* there will be two options to select to encrypt any message.
* and the key will be required to compelete the process.
* the second one is to decrype the cipher text using specific key.
* 
* this impelementation based on long long data type
* Autho : Karim Mohamed Amin
* Date : 28/11/2021
****************************************************************************************************************/
#include<stdio.h>
#include <stdlib.h>
#ifdef __GNUC__
# define __rdtsc  __builtin_ia32_rdtsc
#else
#include<intrin.h>
#endif
/**********************************************************************
*                               Definitions                           *
***********************************************************************/
#define BASE 16
#define DES_NUM_OF_STAGES 16
typedef unsigned long long u64;
typedef unsigned long u32;
/**********************************************************************
*                               Function Prototypes                   *
***********************************************************************/
u64 read_u64_hex(const char* data);
u64 permuate(u64 in , int input_size , const int* table, int table_size);
u64 encrypt(u64 plain_text, const u64 sub_keys[16]);
u32 circularShiftLeft(u32 input, int num_shifts);
u32 substitutionPermuted(u64 in,int* s_box_table);
void generate_subkeys(u64 main_key, u64* sub_keys);
void reverse_keys(u64* original_keys, u64* reversed_keys);
/**********************************************************************
*                               tables standard		                   *
***********************************************************************/
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
int substitution_table[512] = { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

                                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

                                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ,

                                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

                                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

                                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

                                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ,

                                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11  };
/* permutaion table*/
int permutaion_table[32] = { 16, 7, 20, 21,
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
/**********************************************************************
*                    the entry point of the program		              *
***********************************************************************/
int main(int argc, char** argv) {
	char* str_key,*plain;
    u64 sub_keys[16],reversed_keys[16];
    u64 plain_text,cipher,key;
    /*take the string in plain to convert it to unsigned long lnog*/
    plain = argv[2];
    /*take the key as string*/
    str_key = argv[3];
    /*take the hexa number in ull var*/
    plain_text = read_u64_hex(plain);
    key = read_u64_hex(str_key);
    generate_subkeys(key, sub_keys);
    if (argv[1] == "encrypt") {
        long long t1 = __rdtsc();
        cipher = encrypt(plain_text, sub_keys);
        long long t2 = __rdtsc();
        printf("cipher: %llx\n", cipher);
        printf("Cycles:%lld\n",t2-t1);
    }
    else if (argv[1] == "decrypt") {
        /*reverse the sub keys*/
        reverse_keys(sub_keys, reversed_keys);
        long long t1 = __rdtsc();
        cipher = encrypt(plain_text, reversed_keys);
        long long t2 = __rdtsc();
        printf("Plain Text: %llx\n", cipher);
        printf("Cycles:%lld\n", t2 - t1);
    }
    else {
        printf("ERROR\n");
    }
	return 0;
}
/*
 * Description : this function will apply the permutaion as required
 *and it will take the input message in binary format
 * finally it will return the text after permutaion in binary format
 */
u64 permuate(u64 in,int input_size, const int* table,int table_size) {
	u64 out = 0;
	int i;
	for (i = 0; i < table_size; i++) {
		out |= (in >> (input_size - table[table_size - 1 - i]) & 1) << i;
	}
	return out;
}
/*
 * Description : this function receives the input_text which is 48 bits and devide them into 8 groups each group is six bits
 * then substitute in the tables ,and permute each group to 4 bits only so we will get 32 bits plain text
 */
u32 substitutionPermuted(u64 in, int* s_box_table){
u32 out = 0;
	int i;
	int* box_adderss,index;
	for (i = 0; i < 8; i++) {
		/*the size of one table is 64 and we have 8 boxes*/
		box_adderss = s_box_table + i * 64;
		/*to get LS six bits*/
		index = in >> ((7 - i) * 6) & 0x3F;
		/*reorder the bits to access one dimensional array*/
		/*b5 b0 b4 b3 b2 b1*/
		index = (index >> 1) & 0x0F | (index & 1) << 4 | index & 0x20;
		out |= (box_adderss[index]<<(4*(7-i)));
	}
    return out;
}
/*
 * Description : this function takes stream of charcaters and converts them into hexa number stored in 
 * unsigned long long data type
 */
u64 read_u64_hex(const char* data) {
	char* stopstring;
	u64 ull = strtoull(data, &stopstring, BASE);
	return ull;
}
/*
* Description : the main goal here is to shift the input text with specific number
* it will take the input text in binary format,and return it in binary format
*/
u32 circularShiftLeft(u32 input, int num_shifts) {
	int i;
	for(i = 0;i<num_shifts;i++)
		input = (input << 1| input>>27) & 0xFFFFFFF;
	return input;
}
/*
* Description : this function do all premutations in DES
* also it generates all subkeys,and impelement all the sixteen rounds
* finally it will return the cipher text.
* Note : i take the subkeys as an argument to be able to encrypt and decrypt with the same function
*/
u64 encrypt(u64 plain_text, const u64 sub_keys[16]) {
    /*now to follow the DES standard we have to split plain text into two halves*/
    u32 left_half_plain;
    u32 right_half_plain;
    /*holds expanded plain text left half*/
    u64 expanded_plain , cipher;
    /*holds the result from the xor operation*/
    u64 xor_result;
    /*to hold the substitution result*/
    u32 substituation_result;
    /*to hold the final permutation in the round*/
    u32 final_permutation;
    /*hold the value of left half palin*/
    u32 right_buffer;
    /*this loop for 16 rounds*/
    /*this is the impelementation for only one round*/
    /*first apply initial permutation*/
    plain_text = permuate(plain_text, 64, initial_permutation_table, 64);
    /*now to follow the DES standard we have to split plain text into two halves*/
    left_half_plain = (plain_text >> 32) & 0xFFFFFFFF;
    right_half_plain = plain_text & 0xFFFFFFFF;
    for (int i = 0; i < DES_NUM_OF_STAGES; i++) {
        right_buffer = right_half_plain;
        /*holds the result form the expansion permutation table and the size will be 48 bits*/
        expanded_plain = permuate(right_half_plain, 32, expansion_permutation_table, 48);
        /*the first xor operation in the round*/
        xor_result = expanded_plain ^ sub_keys[i];
        /*the size of this plain text will be 32 bits again */
        substituation_result = substitutionPermuted(xor_result, substitution_table);
        /*last permutation stage*/
        final_permutation = permuate(substituation_result, 32, permutaion_table, 32);
        /*the second xor operation in the round*/
        right_half_plain = left_half_plain ^ final_permutation;
        left_half_plain = right_buffer;
    }
    /*32 bits final swap & swap the two halves */
    plain_text = ((u64)right_half_plain<<32)|(left_half_plain&  0xFFFFFFFF);
    /*final inverse permutation*/
    cipher = permuate(plain_text, 64, inverse_init_perm_table, 64);
    return cipher;
}
/*
 * Description : to generate 16 subkeys from the main key
 */
void generate_subkeys(u64 main_key , u64 * sub_keys) {
    u64 compresed_key;
    u32 left_half , right_half;
    /*apply left circular shift using the table above each key will be 56 bits*/
    u32 right_shifted_keys[DES_NUM_OF_STAGES];
    u32 left_shifted_keys[DES_NUM_OF_STAGES];
    /*apply permutation choice 1 the size of compersed key is 56 bits*/
    compresed_key = permuate(main_key,64,premuted_choice1_table,56);
    /*split the main key into two halves*/
    left_half = (compresed_key >> 28) & 0xFFFFFFF;
    right_half = (compresed_key) & 0xFFFFFFF;
    /*first time i will left shit the original two halves from the key*/
    left_shifted_keys[0] = circularShiftLeft(left_half, shift_table[0]);
    right_shifted_keys[0] = circularShiftLeft(right_half, shift_table[0]);
    /*an overflow occurs here so we have to cast the result of shifting*/
    sub_keys[0] = ((u64)left_shifted_keys[0]<<28) | (right_shifted_keys[0] & 0xFFFFFFF);
    /*then i will left shit the pervious shifted keys*/
    for (int i = 1; i < DES_NUM_OF_STAGES; i++) {
        left_shifted_keys[i] = circularShiftLeft(left_shifted_keys[i - 1], shift_table[i]);
        right_shifted_keys[i] = circularShiftLeft(right_shifted_keys[i - 1], shift_table[i]);
        sub_keys[i] = ((u64)left_shifted_keys[i] << 28)| (right_shifted_keys[i] & 0xFFFFFFF);
    }
    /*apply premutation choice 2 this key will be 48 bits*/
    for (int i = 0; i < DES_NUM_OF_STAGES; i++) {
        //subkeys.push_back(getPermuted(shifted_keys[i], premuted_choice2_table, 48));
        sub_keys[i] = permuate(sub_keys[i], 56, premuted_choice2_table, 48);
    }
}
/*
 * Describtion :reversing the subkeys used in encryption to be able to decrypt the cipher text
 */
void reverse_keys(u64* original_keys, u64* reversed_keys) {
    for (int i = 0; i < 16; i++) {
        reversed_keys[16 - 1 - i] = original_keys[i];
    }
}