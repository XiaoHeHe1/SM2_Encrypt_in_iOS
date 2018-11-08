
#include "part4.h"
#include <openssl/rand.h>

typedef struct 
{
	BYTE *message;
	int message_byte_length;
	//BYTE *encrypt;
	BYTE *decrypt;
	int klen_bit;

	BYTE k[MAX_POINT_BYTE_LENGTH];  //ÀÊª˙ ˝
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct 
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	}public_key;

	BYTE C[102411];   //thissss // C_1 || C_2 || C_3
	BYTE C_1[1024];
	BYTE C_2[102411]; //thissss //º”√‹∫Ûµƒœ˚œ¢
	BYTE C_3[1024];

} message_st;

int sm2_encrypt(ec_param *ecp, message_st *message_data)
{
	BIGNUM *P_x;
	BIGNUM *P_y;
	//BIGNUM *d;
	BIGNUM *k;
	xy_ecpoint *P;
	xy_ecpoint *xy1;
	xy_ecpoint *xy2;
	int pos1;
	BYTE *t;
	int i;
	sm2_hash local_C_3;

	P_x = BN_new();
	P_y = BN_new();
	k = BN_new();
	P = xy_ecpoint_new(ecp);
	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);

	BN_bin2bn(message_data->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(message_data->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(message_data->k, ecp->point_byte_length, k);

	xy_ecpoint_init_xy(P, P_x, P_y, ecp);
	xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
	xy_ecpoint_mul_bignum(xy2, P, k, ecp);

	pos1 = 0;
	message_data->C_1[0] = '\x04';
	pos1 = pos1 + 1;
	BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->x);
	BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->y);

	pos1 = 0;
    
    //thissssmessage_data->C_2 = malloc(message_data->message_byte_length );//20170317
    
	BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->y);

	t = KDF((BYTE *)message_data->C_2, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);
	for (i = 0; i < message_data->message_byte_length; i++)
	{
		message_data->C_2[i] = t[i] ^ message_data->message[i];
	}
	OPENSSL_free(t);

	//º∆À„C_3
	memset(&local_C_3, 0, sizeof(local_C_3));
    
    //thisssslocal_C_3.buffer = malloc(ecp->point_byte_length + message_data->message_byte_length + ecp->point_byte_length);//20170317
    
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length
		, xy2->x);
	BUFFER_APPEND_STRING(local_C_3.buffer, local_C_3.position, message_data->message_byte_length
		, message_data->message);
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length
		, xy2->y);
	SM3_Init();
	SM3_Update((BYTE *)local_C_3.buffer, local_C_3.position);
	SM3_Final_byte(local_C_3.hash);
	memcpy(message_data->C_3, (char *)local_C_3.hash, HASH_BYTE_LENGTH);

	pos1 = 0;
    
    //thissssmessage_data->C = malloc(1 + ecp->point_byte_length + ecp->point_byte_length + message_data->message_byte_length + HASH_BYTE_LENGTH);//20170317
    
	BUFFER_APPEND_STRING(message_data->C, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length
		, message_data->C_1);
	BUFFER_APPEND_STRING(message_data->C, pos1, message_data->message_byte_length
		, message_data->C_2);
	BUFFER_APPEND_STRING(message_data->C, pos1, HASH_BYTE_LENGTH
		, message_data->C_3);

	printf("encrypt: \n");
	DEFINE_SHOW_STRING(message_data->C, 1 + ecp->point_byte_length + ecp->point_byte_length +message_data->message_byte_length+ HASH_BYTE_LENGTH );

	BN_free(P_x);
	BN_free(P_y);
	BN_free(k);
	xy_ecpoint_free(P);
	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);

	return SUCCESS;
}

int sm2_decrypt(ec_param *ecp, message_st *message_data)
{
	int pos1;
	int pos2;
	xy_ecpoint *xy1;
	xy_ecpoint *xy2;
	BIGNUM *d;
	BYTE KDF_buffer[MAX_POINT_BYTE_LENGTH * 2];
	BYTE *t;
	int i;

	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);
	d = BN_new();

	pos1 = 0;
	pos2 = 0;
	BUFFER_APPEND_STRING(message_data->C_1, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length
		, &message_data->C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
    
    //thissssmessage_data->C_2 = malloc(message_data->message_byte_length);//0317
    
	BUFFER_APPEND_STRING(message_data->C_2, pos1, message_data->message_byte_length
		, &message_data->C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C_3, pos1, HASH_BYTE_LENGTH
		, &message_data->C[pos2]);
	pos2 = pos2 + pos1;

	BN_bin2bn(&message_data->C_1[1], ecp->point_byte_length, xy1->x);
	BN_bin2bn(&message_data->C_1[1 + ecp->point_byte_length], ecp->point_byte_length, xy1->y);

	BN_bin2bn(message_data->private_key, ecp->point_byte_length, d);
	xy_ecpoint_init_xy(xy1, xy1->x, xy1->y, ecp);
	xy_ecpoint_mul_bignum(xy2, xy1, d, ecp);

	pos1 = 0;
	memset(KDF_buffer, 0, sizeof(KDF_buffer));
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->y);
	DEFINE_SHOW_BIGNUM(d);
	DEFINE_SHOW_BIGNUM(xy2->x);
	DEFINE_SHOW_BIGNUM(xy2->y);
	t = KDF((BYTE *)KDF_buffer, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);

	for (i = 0; i < message_data->message_byte_length; i++)
	{
		message_data->decrypt[i] = t[i] ^ message_data->C_2[i];
	}
	OPENSSL_free(t);

	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);
	BN_free(d);

	return SUCCESS;
}

void test_part4(char **sm2_param, int type, int point_bit_length)
{
	ec_param *ecp;
	sm2_ec_key *key_B;
	message_st message_data;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	key_B = sm2_ec_key_new(ecp);
	sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);

	memset(&message_data, 0, sizeof(message_data));
	message_data.message = (BYTE *)message;
	message_data.message_byte_length = strlen((char *)message_data.message);
	message_data.klen_bit = message_data.message_byte_length * 8;
	sm2_hex2bin((BYTE *)sm2_param_k[ecp->type], message_data.k, ecp->point_byte_length);
	sm2_bn2bin(key_B->d, message_data.private_key, ecp->point_byte_length);
	sm2_bn2bin(key_B->P->x, message_data.public_key.x, ecp->point_byte_length);
	sm2_bn2bin(key_B->P->y, message_data.public_key.y, ecp->point_byte_length);
	DEFINE_SHOW_BIGNUM(key_B->d);
	DEFINE_SHOW_BIGNUM(key_B->P->x);
	DEFINE_SHOW_BIGNUM(key_B->P->y);

	message_data.decrypt = (BYTE *)OPENSSL_malloc(message_data.message_byte_length + 1);
	memset(message_data.decrypt, 0, message_data.message_byte_length+1);

	sm2_encrypt(ecp, &message_data);
	sm2_decrypt(ecp, &message_data);

	printf("decrypt: len: %d\n%s\n", strlen(message_data.decrypt), message_data.decrypt);
	OPENSSL_free(message_data.decrypt);

	sm2_ec_key_free(key_B);
	ec_param_free(ecp);
}
void sm2JiaMi(char **sm2_param, int type, int point_bit_length , char *mingwen,char *miwen)

{
    ec_param *ecp;
    sm2_ec_key *key_B;
    message_st message_data;

    ecp = ec_param_new();
    ec_param_init(ecp, sm2_param, type, point_bit_length);
    key_B = sm2_ec_key_new(ecp);
 
//用私钥和随机数导出一个公钥，实际应用时没有私钥，也就是没有这行代码，直接设置下面的公钥
    sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);//把中间的值给key_b的b

    
    memset(&message_data, 0, sizeof(message_data));
//设置明文 这里输入一个字符串 如果输入char[]需要稍微改动
    message_data.message = (BYTE *)mingwen;

    message_data.message_byte_length = (int)strlen((char *)message_data.message);
    message_data.klen_bit = message_data.message_byte_length * 8;

    
//随机数 拷贝到message_data.k,实际使用时应该随机生成这个数
    sm2_hex2bin((BYTE *)sm2_param_k[ecp->type], message_data.k, ecp->point_byte_length);

//设置公钥
    sm2_bn2bin(key_B->P->x, message_data.public_key.x, ecp->point_byte_length);
    sm2_bn2bin(key_B->P->y, message_data.public_key.y, ecp->point_byte_length);
    DEFINE_SHOW_BIGNUM(key_B->P->x);//公钥PB =(xB ,yB ): 坐标xB :
    DEFINE_SHOW_BIGNUM(key_B->P->y);//坐标yB :
//加密
    sm2_encrypt(ecp, &message_data);
    memcpy(miwen, message_data.C, sizeof(message_data.C));

    
    sm2_ec_key_free(key_B);
    ec_param_free(ecp);

}
void sm2JiemiWithPrivateKey(char **sm2_param, int type, int point_bit_length , char *miwen , char pri[],char output[],int mingWENplainlength ){
    
    ec_param *ecp;
    sm2_ec_key *key_B;
    message_st message_data;
    //ecp的开辟空间p a b n
    ecp = ec_param_new();
    //ecp 给 pabn设置标准值
    ec_param_init(ecp, sm2_param, type, point_bit_length);
    //给dp开辟空间
    key_B = sm2_ec_key_new(ecp);
    
    //设置自己传入的私钥
    //设置私钥，把中间的值给key_b的b
    sm2_ec_key_init(key_B, pri, ecp);
    
    
    memset(&message_data, 0, sizeof(message_data));
    
    //明文的长度，这个长度应该根据密文计算，这里固定写6
    message_data.message_byte_length = mingWENplainlength;
    
    //k的比特长度是明文长度*8
    message_data.klen_bit = message_data.message_byte_length * 8;
    
    //设置私钥,解密和公钥和随机数无关
    sm2_bn2bin(key_B->d, message_data.private_key, ecp->point_byte_length);
    //私钥dB :
    DEFINE_SHOW_BIGNUM(key_B->d);
    //给解密后的明文开辟空间
    message_data.decrypt = (BYTE *)OPENSSL_malloc(message_data.message_byte_length + 1);
    memset(message_data.decrypt, 0, message_data.message_byte_length+1);//置为0
    
    int hehelength = mingWENplainlength +64 +32+1;
    
//    message_data.C = malloc(hehelength);//thissss//0317
    
    //设置密文
    for (int i = 0; i < hehelength; i++)
    {
        message_data.C[ i] =  miwen[i];
    }
    
//    DEFINE_SHOW_STRING(message_data.C, hehelength);
    
    sm2_decrypt(ecp, &message_data);
    
    memcpy(output, message_data.decrypt, hehelength);
    
    OPENSSL_free(message_data.decrypt);
    
    sm2_ec_key_free(key_B);
    ec_param_free(ecp);
    
    
    
    
    
    
    

}
void sm2Jiemi(char **sm2_param, int type, int point_bit_length , char *miwen ,char output[] ){
    ec_param *ecp;
    sm2_ec_key *key_B;
    message_st message_data;
    //ecp的开辟空间p a b n
    ecp = ec_param_new();
    //ecp 给 pabn设置标准值
    ec_param_init(ecp, sm2_param, type, point_bit_length);
    //给dp开辟空间
    key_B = sm2_ec_key_new(ecp);
    
    //设置私钥，把中间的值给key_b的b
    sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);
    
    
    memset(&message_data, 0, sizeof(message_data));
    
    //明文的长度，这个长度应该根据密文计算，这里固定写6
    message_data.message_byte_length = 6;
    //k的比特长度是明文长度*8
    message_data.klen_bit = message_data.message_byte_length * 8;
 
    //设置私钥,解密和公钥和随机数无关
    sm2_bn2bin(key_B->d, message_data.private_key, ecp->point_byte_length);
    //私钥dB :
    DEFINE_SHOW_BIGNUM(key_B->d);
    //给解密后的明文开辟空间
    message_data.decrypt = (BYTE *)OPENSSL_malloc(message_data.message_byte_length + 1);
    memset(message_data.decrypt, 0, message_data.message_byte_length+1);//置为0

    //设置密文
    for (int i = 0; i < 256; i++)
    {
        message_data.C[ i] =  miwen[i];
    }

    DEFINE_SHOW_STRING(message_data.C, 256);

    sm2_decrypt(ecp, &message_data);

    memcpy(output, message_data.decrypt, 100);
    
    OPENSSL_free(message_data.decrypt);

    sm2_ec_key_free(key_B);
    ec_param_free(ecp);
}
//使用传入的公钥加密
void sm2JiaMiWithPublicKey(char **sm2_param, int type, int point_bit_length , char mingwen[],int mingwenlength,char *miwen,unsigned char px[],unsigned char py[]){
    
    ec_param *ecp;
    sm2_ec_key *key_B;
    message_st message_data;
    
    ecp = ec_param_new();
    ec_param_init(ecp, sm2_param, type, point_bit_length);
    
    key_B = sm2_ec_key_new(ecp);
    
    sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);
    
    
    memset(&message_data, 0, sizeof(message_data));
    
    message_data.message = (BYTE*)mingwen;
//    memcpy(message_data.message, mingwen,strlen(mingwen) );
    
    
    message_data.message_byte_length = mingwenlength;//20170317
    
    
    message_data.klen_bit = message_data.message_byte_length * 8;
    
    //这个是固定的随机数
    //sm2_hex2bin((BYTE *)sm2_param_k[ecp->type], message_data.k, ecp->point_byte_length);
    
    //随机数种子
    static const char rnd_seed[] = "random num c random num seed random num c random num seed";

    RAND_seed(rnd_seed, sizeof rnd_seed);
    unsigned char suijishu[32];
    //生成随机数
    RAND_pseudo_bytes(suijishu,32);
    for( int i=0;i<sizeof suijishu;i++){
        //printf("%02x", suijishu[i]);
        message_data.k[i]=suijishu[i];
    }
    printf("\n");
    DEFINE_SHOW_STRING(message_data.k, sizeof(message_data.k));
    
    
    
    //设置px
    //printf("px\n");
    for( int i=0;i<32;i++){
        //printf("%02x", px[i]);
        message_data.public_key.x[i]=px[i];
    }
    //printf("\n");
    
    //设置py
    //printf("py\n");
    for( int i=0;i<32;i++){
        //printf("%02x", py[i]);
        message_data.public_key.y[i]=py[i];
    }
    //printf("\n");
    
    
    DEFINE_SHOW_BIGNUM(key_B->P->x);//公钥PB =(xB ,yB ): 坐标xB :
    DEFINE_SHOW_BIGNUM(key_B->P->y);//坐标yB :
    DEFINE_SHOW_STRING(message_data.public_key.x, 32);
    DEFINE_SHOW_STRING(message_data.public_key.y, 32);
    
    sm2_encrypt(ecp, &message_data);
    

    
    memcpy(miwen, message_data.C,message_data.message_byte_length  +64 +32 +2);
//
    sm2_ec_key_free(key_B);
    ec_param_free(ecp);
}

