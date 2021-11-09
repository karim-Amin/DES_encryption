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
*                               Function Prototypes                   *
***********************************************************************/
string convertBinToHex(string bin);
string convertHexToBin(string hex);
int main()
{
    string hex = "5F";
    string bin = convertHexToBin(hex);
    cout << bin;
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
