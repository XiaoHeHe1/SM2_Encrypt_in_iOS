#ifndef PART2_H
#define PART2_H

#include "sm2.h"

void test_part2(char **sm2_param, int type, int point_bit_length);


void sm2Sign(char userAid[],int userIdDataLength,char mingwen[],int mingwenDataLength,unsigned char pa[],unsigned char px[],unsigned char py[],char *singResultR,char *singResultS);



int sm2CheckSign(char userAid[],int userIdDataLength,char mingwen[],int mingwenDataLength,unsigned char px[],unsigned char py[],char *singResultR,char *singResultS);
    
#endif;
