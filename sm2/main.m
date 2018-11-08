//
//  main.m
//  sm2
//
//  Created by yfc on 16/7/11.
//  Copyright © 2016年 yfc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#import "part4.h"
#import "part2.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ebcdic.h>
#include <openssl/ecdsa.h>

/*Sm2 中指定的参数 确定下y2 = x3 + ax + b 曲线*/
#define _P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"

#define _a  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"

#define _b  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"

#define _n  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

#define _Gx "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"

#define _Gy "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"



int sm2_gen_key()
{
    int ret = -1;
    EC_KEY* key = NULL;
    BN_CTX *ctx = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* point_p = NULL;
    const EC_POINT *point_q = NULL;
    BIGNUM *p, *a, *b, *gx, *gy, *z;
    
    //    assert(sm2key);
    
    p = BN_new();
    a = BN_new();
    b = BN_new();
    
    gx = BN_new();
    gy = BN_new();
    z = BN_new();
    
    //初始化一个空算法组
    group = EC_GROUP_new(EC_GFp_mont_method());
    
    //将国密算法的参数转为大数
    BN_hex2bn(&p, _P);
    BN_hex2bn(&a, _a);
    BN_hex2bn(&b, _b);
    BN_hex2bn(&gx, _Gx);
    BN_hex2bn(&gy, _Gy);
    BN_hex2bn(&z, _n); //素数P的阶
    
    ctx = BN_CTX_new();
    
    //先确定sm2曲线
    //传入a，b参数
    if (!EC_GROUP_set_curve_GFp(group, p, a, b,ctx))
    {
        goto err_process;
    }
    
    //取曲线上的三个点
    point_p = EC_POINT_new(group);
    
    //设置基点坐标
    if (!EC_POINT_set_affine_coordinates_GFp(group, point_p, gx, gy, ctx))
    {
        goto err_process;
    }
    //
    ////确定P点事否在曲线上
    if (!EC_POINT_is_on_curve(group, point_p, ctx))
    {
        ret = -2;
        goto err_process;
    }
    
    //设置椭圆曲线的基G，完成了国密曲线
    if(!EC_GROUP_set_generator(group, point_p, z, BN_value_one()))
    {
        ret = -3;
        goto err_process;
    }
    
    //生成国密Key
    key = EC_KEY_new();
    if (!EC_KEY_set_group(key, group))
    {
        ret = -4;
        goto err_process;
    }
    
    if(!EC_KEY_generate_key(key))
    {
        ret = -5;
        goto err_process;
    }
    
    printf("gen key success:\n the prv is %s\n",
           BN_bn2hex(EC_KEY_get0_private_key(key)));
    
    
    BYTE bufferPri[1024];
    BYTE bufferPubX[1024];
    BYTE bufferPubY[1024];
    
    
    //     BN_bn2bin(EC_KEY_get0_private_key(key), &bufferPri[1024]);
    //    DEFINE_SHOW_STRING(bufferPri, 64);
    
    point_q = EC_KEY_get0_public_key(key);
    if(!EC_POINT_get_affine_coordinates_GFp(group, point_q, gx, gy , NULL))
    {
        goto err_process;
    }
    
    printf("gx is %s\n", BN_bn2hex(gx));
    printf("gy is %s\n", BN_bn2hex(gy));
    
    
    
    //    BN_bn2bin(gx, &bufferPubX[1024]);
    //    DEFINE_SHOW_STRING(bufferPubX, 64);
    //
    //    BN_bn2bin(gy, &bufferPubY[1024]);
    //    DEFINE_SHOW_STRING(bufferPubY, 64);
    
    ret = 0;
    
err_process:
    
    if (point_p != NULL)
    {
        EC_POINT_free(point_p);
    }
    
    if (group != NULL)
    {
        EC_GROUP_free(group);
    }
    
    if (ctx != NULL)
    {
        BN_CTX_free(ctx);
    }
    
    if (key != NULL)
    {
        EC_KEY_free(key);
    }
    
    return ret;
}
int main(int argc, char * argv[]) {
    @autoreleasepool {
        
        //生成公钥私钥yu
        sm2_gen_key();
        
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
