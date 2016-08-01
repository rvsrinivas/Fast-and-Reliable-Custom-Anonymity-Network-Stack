#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include "des.h"


DES_key_schedule schedule;
unsigned char key[8];
unsigned char ivdata[8];


void initDes(){
    int i;
    DES_string_to_key("558LFin@l", &key);
    DES_set_key_checked(&key, &schedule);
    for (i = 0; i < 8 ; i++)
        ivdata[i] = 0x00;
}

void encrypt(const unsigned char *pt, unsigned char *ct, long length){
    DES_cbc_encrypt(pt, ct, length, &schedule, &ivdata, 1);
}

void decrypt(const unsigned char *ct, unsigned char *pt, long length){
    DES_cbc_encrypt(ct, pt, length, &schedule, &ivdata, 0);
}

int testDes()
{
    init();
    int i;
    unsigned char input[120];
    unsigned char output[128];
    unsigned char input2[120];

//    for (i = 0; i < 120 ; i++){
//        input[i] = (u_char) (rand() & 0xff);
//    }

    memcpy(input, "My name is Vidhi. I am not sure if this is 120 characters long", 120);
    int size = sizeof(input);
    printf("cleartext:%s \n", input);

    encrypt((const u_char *)input, output, 120);

    printf("ciphertext: ");

    for (i = 0; i < size; i++)
         printf("%02x", output[i]);
    printf("\n");

    decrypt((const u_char *)output, input2, 120);
    printf("cleartext:%s \n", input2);
    return 0;
}
