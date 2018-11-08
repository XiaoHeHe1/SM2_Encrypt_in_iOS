#include "part2.h"
#include "sm2_ec_key.h"

typedef struct 
{
	BYTE *message;
	int message_byte_length;
	BYTE *ID;
	int ENTL;
	BYTE k[MAX_POINT_BYTE_LENGTH];  //«©√˚÷–≤˙…˙ÀÊª˙ ˝
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct 
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	}public_key;
	BYTE Z[HASH_BYTE_LENGTH];
	BYTE r[MAX_POINT_BYTE_LENGTH];
	BYTE s[MAX_POINT_BYTE_LENGTH];
	BYTE R[MAX_POINT_BYTE_LENGTH];
} sm2_sign_st;

void sm2_sign(ec_param *ecp, sm2_sign_st *sign_yu ,unsigned char *singResultRR,char *singResultSS)
{
	sm2_hash Z_A;
	sm2_hash e;
	BIGNUM *e_bn;

	BIGNUM *r;
	BIGNUM *s;
	BIGNUM *tmp1;

	BIGNUM *P_x;
	BIGNUM *P_y;
	BIGNUM *d;
	BIGNUM *k;
	xy_ecpoint *xy1;

	e_bn = BN_new();
	r = BN_new();
	s = BN_new();
	tmp1 = BN_new();
	P_x = BN_new();
	P_y = BN_new();
	d = BN_new();
	k = BN_new();
	xy1 = xy_ecpoint_new(ecp);

	BN_bin2bn(sign_yu->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(sign_yu->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(sign_yu->private_key, ecp->point_byte_length, d);
	BN_bin2bn(sign_yu->k, ecp->point_byte_length, k);

    //userid
	memset(&Z_A, 0, sizeof(Z_A));
	Z_A.buffer[0] = ((sign_yu->ENTL * 8) >> 8) & 0xFF;
	Z_A.buffer[1] = (sign_yu->ENTL * 8) & 0xFF;
	Z_A.position = Z_A.position + 2;
	BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, sign_yu->ENTL, sign_yu->ID);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->a);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->b);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->x);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->y);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_x);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_y);
	DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
	SM3_Init();
	SM3_Update(Z_A.buffer, Z_A.position);
	SM3_Final_byte(Z_A.hash);
	memcpy(sign_yu->Z, Z_A.hash, HASH_BYTE_LENGTH);

	DEFINE_SHOW_STRING(Z_A.hash, HASH_BYTE_LENGTH);

	memset(&e, 0, sizeof(e));
	BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, Z_A.hash);
    BUFFER_APPEND_STRING(e.buffer, e.position, sign_yu->message_byte_length, sign_yu->message);//这里以前写死了
    
    
	SM3_Init();
	SM3_Update(e.buffer, e.position);
	SM3_Final_byte(e.hash);
	DEFINE_SHOW_STRING(e.hash, HASH_BYTE_LENGTH);
	DEFINE_SHOW_STRING(sign_yu->k, ecp->point_byte_length);

	BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);

	xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
    BN_zero(r);
	BN_mod_add(r, e_bn, xy1->x, ecp->n, ecp->ctx);

	BN_one(s);
	BN_add(s, s, d);
	BN_mod_inverse(s, s, ecp->n, ecp->ctx);  //«Ûƒ£∑¥

	BN_mul(tmp1, r, d, ecp->ctx);
	BN_sub(tmp1, k, tmp1);
	BN_mod_mul(s, s, tmp1, ecp->n, ecp->ctx);

	sm2_bn2bin(r, sign_yu->r, ecp->point_byte_length);
	sm2_bn2bin(s, sign_yu->s, ecp->point_byte_length);

    
	DEFINE_SHOW_BIGNUM(r);
	DEFINE_SHOW_BIGNUM(s);

    //yu
    char *to = BN_bn2hex(r);
    
    memcpy(singResultRR, to, 64);
    
    char *to2 = BN_bn2hex(s);
    
    memcpy(singResultSS, to2, 64);
    
    printf("px\n");
    for( int i=0;i<64;i++){
        printf("%c", singResultRR[i]);
    }
    printf("\n");
    

    
	BN_free(e_bn);
	BN_free(r);
	BN_free(s);
	BN_free(tmp1);
	BN_free(P_x);
	BN_free(P_y);
	BN_free(d);
	BN_free(k);
	xy_ecpoint_free(xy1);
}

//这里面打印比较多，因为遇到一个问题
void sm2_verify(ec_param *ecp, sm2_sign_st *sign,char *singResulR)
{
	sm2_hash e;
	BIGNUM *e_bn;
	BIGNUM *t;
	BIGNUM *R;
	xy_ecpoint *result;
	xy_ecpoint *result1;
	xy_ecpoint *result2;
	xy_ecpoint *P_A;
	BIGNUM *r;
	BIGNUM *s;
	BIGNUM *P_x;
	BIGNUM *P_y;

	e_bn = BN_new();
	t = BN_new();
	R = BN_new();
	result = xy_ecpoint_new(ecp);
	result1 = xy_ecpoint_new(ecp);
	result2 = xy_ecpoint_new(ecp);
	P_A = xy_ecpoint_new(ecp);
	r = BN_new();
	s = BN_new();
	P_x = BN_new();
	P_y = BN_new();

    //bignum和byte转换 r s x y
	BN_bin2bn(sign->r, ecp->point_byte_length, r);
	BN_bin2bn(sign->s, ecp->point_byte_length, s);
	BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
	xy_ecpoint_init_xy(P_A, P_x, P_y, ecp);

    
    //wo复制过来 的  获取sign z  与 z_a
    sm2_hash Z_A;
    memset(&Z_A, 0, sizeof(Z_A));
    Z_A.buffer[0] = ((sign->ENTL * 8) >> 8) & 0xFF;
    Z_A.buffer[1] = (sign->ENTL * 8) & 0xFF;
    Z_A.position = Z_A.position + 2;
    BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, sign->ENTL, sign->ID);
    BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->a);
    BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->b);
    BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->x);
    DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
//    0090414C 49434531 32334059 41484F4F 2E434F4D 787968B4 FA32C3FD 2417842E
//    73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498 63E4C6D3 B23B0C84 9CF84241
//    484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A 421DEBD6 1B62EAB6 746434EB
//    C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D
    BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->y);
    DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
//    0090414C 49434531 32334059 41484F4F 2E434F4D 787968B4 FA32C3FD 2417842E
//    73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498 63E4C6D3 B23B0C84 9CF84241
//    484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A 421DEBD6 1B62EAB6 746434EB
//    C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D 0680512B CBB42C07 D47349D2
//    153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2
    BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_x);
    DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
    //p_x0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A
    BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_y);
    //py  7C0240F8 8F1CD4E1 6352A73C  17B7F16F 07353E53 A176D684 A9FE0C6B B798E857
    DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
//    0090414C 49434531 32334059 41484F4F 2E434F4D 787968B4 FA32C3FD 2417842E
//    73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498 63E4C6D3 B23B0C84 9CF84241
//    484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A 421DEBD6 1B62EAB6 746434EB
//    C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D 0680512B CBB42C07 D47349D2
//    153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2 //后面不一样0AE4C779 8AA0F119 471BEE11
//    825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A 7C0240F8 8F1CD4E1 6352A73C
//    17B7F16F 07353E53 A176D684 A9FE0C6B B798E857
    
    
    SM3_Init();
    SM3_Update(Z_A.buffer, Z_A.position);
    SM3_Final_byte(Z_A.hash);
    
    memcpy(sign->Z, Z_A.hash, HASH_BYTE_LENGTH);
    
    DEFINE_SHOW_STRING(Z_A.hash, HASH_BYTE_LENGTH);//F4A38489 E32B45B6 F876E3AC 2168CA39 2362DC8F 23459C1D 1146FC3D BFB7BC9A // 不一样

    
    //wo复制过来 的
    

    
    //z是杂凑值  和msg
	memset(&e, 0, sizeof(e));
	BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, sign->Z);
	BUFFER_APPEND_STRING(e.buffer, e.position, sign->message_byte_length, (BYTE*)sign->message);
    
    DEFINE_SHOW_STRING(sign->Z, HASH_BYTE_LENGTH);//F4A38489 E32B45B6 F876E3AC 2168CA39 2362DC8F 23459C1D 1146FC3D BFB7BC9A
    DEFINE_SHOW_STRING(e.buffer, HASH_BYTE_LENGTH + 100);//F4A38489 E32B45B6 F876E3AC 2168CA39 2362DC8F 23459C1D 1146FC3D BFB7BC9A  6D657373 61676520 64696765 73740000
    DEFINE_SHOW_STRING(e.hash, HASH_BYTE_LENGTH);//0
    
	SM3_Init();
	SM3_Update(e.buffer, e.position);
	SM3_Final_byte(e.hash);
	BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);
    
    

    DEFINE_SHOW_STRING(e.buffer, HASH_BYTE_LENGTH);//E6E831E4 6D338322 F431ED5A C3364483 E9372D4B 7795EF54 5D68E91C 583A6693

    DEFINE_SHOW_STRING(e.hash, HASH_BYTE_LENGTH);//B524F552 CD82B8B0 28476E00 5C377FB1 9A87E6FC 682D48BB 5D42E3D9 B9EFFE76

    
    
    
//	DEFINE_SHOW_BIGNUM(e_bn);
    DEFINE_SHOW_BIGNUM(e_bn);//B524F552 CD82B8B0 28476E00 5C377FB1 9A87E6FC 682D48BB 5D42E3D9 B9EFFE76

    
    
    
	BN_mod_add(t, r, s, ecp->n, ecp->ctx);
    DEFINE_SHOW_BIGNUM(result1->x);
    DEFINE_SHOW_BIGNUM(result1->y);
    DEFINE_SHOW_BIGNUM(ecp->G->x);//32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
    DEFINE_SHOW_BIGNUM(ecp->G->y);//BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
    DEFINE_SHOW_BIGNUM(s);//2BF329F4 AFF86EEE 0F924888 DDE20BF1 2A21B638 A3B0F1FC A70395C4 BE00D0AC
    DEFINE_SHOW_BIGNUM(result2->x);
    DEFINE_SHOW_BIGNUM(result2->y);
    DEFINE_SHOW_BIGNUM(P_A->x);//D5548C78 25CBB561 50A3506C D57464AF 8A1AE051 9DFAF3C5 8221DC81 0CAF28DD
    DEFINE_SHOW_BIGNUM(P_A->y);//92107376 8FE3D59C E54E79A4 9445CF73 FED23086 53702726 4D168946 D479533E
    DEFINE_SHOW_BIGNUM(t);//336ECE5A 134949DC B2F7B769 20BFF8D3 57804402 EC33BD1C AF0E6832 EAB6FF4B
    DEFINE_SHOW_BIGNUM(result->x);
    DEFINE_SHOW_BIGNUM(result->y);
    
	xy_ecpoint_mul_bignum(result1, ecp->G, s, ecp);
    
    DEFINE_SHOW_BIGNUM(result1->x);//68D957D2 FA010371 C76F7B1C 9370D4B5 35E2A712 9FB7627A BF76F27B BC33A660
    DEFINE_SHOW_BIGNUM(result1->y);//8BB516B0 ABBD3CCE 34415612 F439203A FDC1BFA2 CBF0EA63 D1C0D07C A2E32FCC
    DEFINE_SHOW_BIGNUM(result2->x);
    DEFINE_SHOW_BIGNUM(result2->y);
    DEFINE_SHOW_BIGNUM(result->x);
    DEFINE_SHOW_BIGNUM(result->y);
    
	xy_ecpoint_mul_bignum(result2, P_A, t, ecp);

    DEFINE_SHOW_BIGNUM(s);
    DEFINE_SHOW_BIGNUM(result2->x);//31F17670 3062F3C8 C375F85E 2F8AA60C 9D8FFA70 DFBB9EA4 E3F9C3E7 7E72D5A8
    DEFINE_SHOW_BIGNUM(result2->y);//6BCCE490 61B56118 B4EC79A9 15B6A102 B8E94A1D 07571C97 5A660947 57B35F6B
    DEFINE_SHOW_BIGNUM(result->x);
    DEFINE_SHOW_BIGNUM(result->y);
    
	xy_ecpoint_add_xy_ecpoint(result, result1, result2, ecp);
    
    DEFINE_SHOW_BIGNUM(result1->x);
    DEFINE_SHOW_BIGNUM(result1->y);
    DEFINE_SHOW_BIGNUM(result->x);//F6A687AB 5744D5CB BA1CF93D 8436416F 75C3AEC3 D762814D 565314AF F57A89F9
    DEFINE_SHOW_BIGNUM(result->y);//F1B8EE05 41740565 491E4404 3DE53CF5 BBEDD613 33071260 DFC5783F 47A7B981
    DEFINE_SHOW_BIGNUM(R);//0
    DEFINE_SHOW_BIGNUM(result->x);//F6A687AB 5744D5CB BA1CF93D 8436416F 75C3AEC3 D762814D 565314AF F57A89F9
    DEFINE_SHOW_BIGNUM(ecp->n);//FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
    
    BN_mod_add(R, e_bn, result->x, ecp->n, ecp->ctx);
    
    DEFINE_SHOW_BIGNUM(e_bn);//10D51CB9 0C0C0522 E94875A2 BEA7AB72 299EBE71 92E64EFE 0573B1C7 7110E5C9 这个也不一样
    DEFINE_SHOW_BIGNUM(R);//077BA465 6350DAEE A3656EE0 42DDECE2 2D5E8DCA 4882CB20 080AD26E 2CB62E9F  就这不一样
    DEFINE_SHOW_BIGNUM(result->x);
    DEFINE_SHOW_BIGNUM(ecp->n);
    
	sm2_bn2bin(R, sign->R, ecp->point_byte_length);

	DEFINE_SHOW_STRING(sign->R, ecp->point_byte_length);

    
    

    
    memcpy(singResulR, sign->R, ecp->point_byte_length);
    
    
	BN_free(e_bn);
	BN_free(t);
	BN_free(R);
	xy_ecpoint_free(result);
	xy_ecpoint_free(result1);
	xy_ecpoint_free(result2);
	xy_ecpoint_free(P_A);
	BN_free(r);
	BN_free(s);
	BN_free(P_x);
	BN_free(P_y);
}
//yu//校验签名
int sm2CheckSign(char userAid[],int userIdDataLength,char mingwen[],int mingwenDataLength,unsigned char px[],unsigned char py[],char *singResultR,char *singResultS){
    ec_param *ecp;
//    sm2_ec_key *key_A;
    sm2_sign_st sign;
    
    ecp = ec_param_new();
    
//   ec_param_init (ecp,sm2_param_fp_256, TYPE_GFp, 256);//pdf例子
    ec_param_init(ecp, sm2_param_recommand, TYPE_GFp, 256);//实际
    
//    key_A = sm2_ec_key_new(ecp);
    
//     sm2_param_digest_d_A[ecp->type]貌似是私钥
//    sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp->type], ecp);
    
    memset(&sign, 0, sizeof(sign));
    
    //设置r s
    for( int i=0;i<32;i++){
    sign.r[i] = singResultR[i];
        printf("%02x", sign.r[i]);
}
    printf("\n");

    for( int i=0;i<32;i++){
        sign.s[i] = singResultS[i];
        printf("%02x", sign.s[i]);

    }
    printf("\n");

    //这是要签名的消息
    sign.message = (BYTE *)mingwen;
    //验证时不用这个参数吗
    
//    for( int i=0;i<32;i++){
//        sign.Z[i] = mingwen[i];
//        printf("%02x", sign.Z[i]);
//        
//    }
    
    
    sign.message_byte_length = mingwenDataLength;
    //这个签名者的id
    sign.ID = (BYTE *)userAid;
    sign.ENTL = userIdDataLength;
    //k 随机数
    sm2_hex2bin((BYTE *)sm2_param_digest_k[ecp->type], sign.k, ecp->point_byte_length);
    
    //设置px
    for( int i=0;i<32;i++){
        sign.public_key.x[i]=px[i];
    }
    //设置py
    for( int i=0;i<32;i++){
        sign.public_key.y[i]=py[i];
    }
    
    memset(sign.private_key, 0, sizeof(sign.private_key)); //«Â≥˝ÀΩ‘ø

    char singResultR_[1024];
    //验证签名
    sm2_verify(ecp, &sign,singResultR_);

    
    for( int i=0;i<32;i++){
        if (singResultR[i] == singResultR_[i]) {
            
            printf("%c", singResultR_[i]);

        }else{
            return 0;
        }
    }
    
    
    
//    sm2_ec_key_free(key_A);
    ec_param_free(ecp);
    
    return 1;
}
//yu
void sm2Sign(char userAid[],int userIdDataLength,char mingwen[],int mingwenDataLength,unsigned char pa[],unsigned char px[],unsigned char py[],char *singResultR,char *singResultS){

    
    ec_param *ecp;
    sm2_ec_key *key_A;
    sm2_sign_st sign;
    
    ecp = ec_param_new();
    ec_param_init(ecp, sm2_param_recommand, TYPE_GFp, 256);
    
    key_A = sm2_ec_key_new(ecp);
    sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp->type], ecp);
    
    memset(&sign, 0, sizeof(sign));
    
    //这是要签名的消息
    sign.message = (BYTE *)mingwen;
//    sign.message_byte_length = strlen(mingwen);
    sign.message_byte_length = mingwenDataLength;
    //这个签名者的id
    sign.ID = (BYTE *)userAid;
//    sign.ENTL = strlen(userAid);
    
    //改成data
    sign.ENTL = userIdDataLength;
    printf("%d",userIdDataLength);
    
    sm2_hex2bin((BYTE *)sm2_param_digest_k[ecp->type], sign.k, ecp->point_byte_length);
    
    //取出私钥 公钥 的值
    //设置pa
    for( int i=0;i<32;i++){
        sign.private_key[i]=pa[i];
    }
    //设置px
    for( int i=0;i<32;i++){
        sign.public_key.x[i]=px[i];
    }
    //设置py
    for( int i=0;i<32;i++){
        sign.public_key.y[i]=py[i];
    }
//    sm2_bn2bin(key_A->d, sign.private_key, ecp->point_byte_length);
//    sm2_bn2bin(key_A->P->x, sign.public_key.x, ecp->point_byte_length);
//    sm2_bn2bin(key_A->P->y, sign.public_key.y, ecp->point_byte_length);
    
    DEFINE_SHOW_STRING(sign.public_key.x, ecp->point_byte_length);
    DEFINE_SHOW_STRING(sign.public_key.y, ecp->point_byte_length);
    
    //dd这里是签名
    char singResultR_[1024];
    char singResultS_[1024];
    sm2_sign(ecp, &sign,singResultR_,singResultS_);
    
    printf("px\n");
    for( int i=0;i<64;i++){
        printf("%c", singResultR_[i]);
    }
    printf("\n");
    
    memcpy(singResultR, singResultR_, 64);
    memcpy(singResultS, singResultS_, 64);
    
    sm2_ec_key_free(key_A);
    ec_param_free(ecp);
    
}
void test_part2(char **sm2_param, int type, int point_bit_length)
{
	ec_param *ecp;
	sm2_ec_key *key_A;
	sm2_sign_st sign;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	key_A = sm2_ec_key_new(ecp);
	sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp->type], ecp);

	memset(&sign, 0, sizeof(sign));
    
    //这是要签名的消息
	sign.message = (BYTE *)message_digest;
	sign.message_byte_length = strlen(message_digest);
    //这个签名者的id
	sign.ID = (BYTE *)ID_A;
	sign.ENTL = strlen(ID_A);
	sm2_hex2bin((BYTE *)sm2_param_digest_k[ecp->type], sign.k, ecp->point_byte_length);
    
    //取出私钥 公钥 的值
	sm2_bn2bin(key_A->d, sign.private_key, ecp->point_byte_length);
	sm2_bn2bin(key_A->P->x, sign.public_key.x, ecp->point_byte_length);
	sm2_bn2bin(key_A->P->y, sign.public_key.y, ecp->point_byte_length);

	DEFINE_SHOW_STRING(sign.public_key.x, ecp->point_byte_length);
	DEFINE_SHOW_STRING(sign.public_key.y, ecp->point_byte_length);
    //这里是签名
//	sm2_sign(ecp, &sign);//改了
    char singResultR_[1024];
    char singResultS_[1024];
    sm2_sign(ecp, &sign,singResultR_,singResultS_);
    
    printf("\n\n\n\n");
    
    
	memset(sign.private_key, 0, sizeof(sign.private_key)); //«Â≥˝ÀΩ‘ø
    //验证签名
//	sm2_verify(ecp, &sign);

	sm2_ec_key_free(key_A);
	ec_param_free(ecp);
}
