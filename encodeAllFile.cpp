#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "encodeAllFile.h"
using namespace std;

#define NUM_ALPHA 180 //max = 180 (180/ 3 * 4 = 240)
#define FIRST_READ (90)
#define MAX_LEN_B64 (256)
#define PRINTLOG 0
unsigned char buffer[NUM_ALPHA + 5];
unsigned char *encoded_data = (unsigned char*) malloc(256);
/**********************************/
// RSA config
 char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
int padding = RSA_PKCS1_PADDING;
unsigned char  encrypted[512]={};

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};
//static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

/************************/
// public encrypt RSA
RSA * createRSA(unsigned char * key, int publicc)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(publicc)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

/****************************/
// encode base 64 function
unsigned char *base64_encode(const unsigned char *data, int input_length, int *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);
    memset(encoded_data, 0, MAX_LEN_B64);
    //unsigned char *encoded_data = (unsigned char*) malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}
/********************************************************************/

string getFileOutNameLHM(string fileIn){
    unsigned int index = 1000000;
    for(unsigned int i = 0; i < fileIn.length(); i++){
        if(fileIn[i] == '.'){
            index = i;
        }
    }
    if(index == 1000000){
        return fileIn;
    }
    string pos = fileIn.substr(0, index);
    string fileType = fileIn.substr(index, fileIn.length() - index);
    return pos + "_encode" + fileType;
}
/******************************************************/

int encodeAllFileLHM(string fileIn){
    string fileOut = getFileOutNameLHM(fileIn);
    FILE * f1 = fopen(fileIn.c_str(), "rb");
    FILE * f2 = fopen(fileOut.c_str(), "wb");
    #if PRINTLOG
        printf("file in = %s\nfileout = %s\n", fileIn.c_str(), fileOut.c_str());
    #endif
    if(f1 == NULL || f2 == NULL){
        #if PRINTLOG
            printf(" flase openfile\n");
        #endif
        return 0;
    }
    int sumReadByte = 0;     
    int num = 0;
    unsigned char *enB64Poi = (unsigned char*) malloc(MAX_LEN_B64 + 5);
    int b64OutLen = 0; // output leng encode base 64
    int encrypted_length = 0;
    int dem = 0;
    printf("\n\n\n----------------Begin Encript---------\n");

    while(1){
        memset(buffer, 0, NUM_ALPHA);
        num = fread(buffer, sizeof(char), NUM_ALPHA, f1);
        if ( num ) {  /* fread success */
            sumReadByte += num;
            buffer[NUM_ALPHA + 1] = '\0';
            if((++dem) < 5){
                for (int i = 0; i < num; i++){
                    printf("%02x %c", buffer[i], (i + 1) % 16 == 0 ? '\n' : '\t');
                }
                printf("\n");
            }
//            fwrite(buffer, sizeof(char), num, f2);  
            memset(enB64Poi, 0, 256);
            enB64Poi = base64_encode(buffer, num, &b64OutLen); 
            if(enB64Poi != NULL){
                #if PRINTLOG
                    printf("step2: encode base 64 success b64OutLen = %d\n", b64OutLen);
                #endif
            } else {
                return 0;
            }

            memset(encrypted, 0, 256);
            encrypted_length = public_encrypt(enB64Poi, b64OutLen, (unsigned char*) publicKey, encrypted);
            if(encrypted_length == -1)
            {
                return 0;
            } else {
                #if PRINTLOG
                    printf("step3: encrypt data success, encrypted_length = %d, Read all %d bytes\n", encrypted_length, sumReadByte);                
                #endif
                fwrite(encrypted, sizeof(char), encrypted_length, f2); 
            }
                   
        } else {  /* fread failed */
            if ( ferror(f1) ){    /* possibility 1 */
                perror( "Error reading myfile" );
                printf("step 4: write date to file out error");
                fclose(f1);
                fclose(f2);
                return 0;
            } else if ( feof(f1)) {  /* possibility 2 */
                perror( "EOF found" );
                printf("read all %d bytes in %s\n", sumReadByte, fileIn.c_str());
                printf("step 4: write date to file out success\n===============>done Encrypt\n\n");
                fclose(f1);
                fclose(f2);
                return 1;
            }
        }
    }
}