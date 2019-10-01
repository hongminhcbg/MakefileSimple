#include "decodeAllFile.h"
#include "encodeAllFile.h"
#include <iostream>
#include <string>
#include <stdio.h>
using namespace std;
int main(int argc, char *argv[]){
    if(argc == 1){
        return 0;
    }
    string s = argv[1];
    if(decodeAllFileLHM(s) ){
        printf("decode success\n");
    } else {
        printf("decode false\n");
    }
}