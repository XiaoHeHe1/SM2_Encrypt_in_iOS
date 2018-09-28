//
//  ViewController.m
//  sm2
//
//  Created by yfc on 16/7/11.
//  Copyright © 2016年 yfc. All rights reserved.
//

#import "ViewController.h"
#import"part4.h"

@interface ViewController ()

@end
#define SCREEN_WIDTH_NEW ([UIScreen mainScreen].bounds.size.width)
#define SCREEN_HEIGHT_NEW ([UIScreen mainScreen].bounds.size.height)
@implementation ViewController
//
//说明：openssl可以引用openssl.framework，也可以引用libcrypto.a+libssl.a
//
- (void)viewDidLoad {
    [super viewDidLoad];

    UIButton *btn = [[UIButton alloc]initWithFrame:CGRectMake(100, 20, 200, 50)];
//    btn.center = self.view.center;
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [btn setTitle:@"点击进行SM2加密解密" forState:UIControlStateNormal];
    btn.layer.cornerRadius = 10;
    btn.backgroundColor = [UIColor orangeColor];
    [self.view addSubview:btn];
    
    [btn addTarget:self action:@selector(btnClicked:) forControlEvents:UIControlEventTouchUpInside];
    
}

- (void)btnClicked:(UIButton*)button {
    
    {
        //使用固定的公钥加密
        NSString *mingwen = @"123457";
        char miwen[1024];
        sm2JiaMi(sm2_param_recommand, TYPE_GFp, 256, [mingwen UTF8String], miwen);
        //密文前面多个04  在用其他工具对密文解密时需要去掉
        NSData *miwendata =  [[NSData alloc]initWithBytes:miwen length: mingwen.length+32+64 +2];
        NSLog(@"密文data=%@",  miwendata );
    }
    
    {
        //使用自己已知的公钥加密和解密
        
        //本例中的私钥是写死的：sm2_param_d_B[2]
            //"00000000008f8b37dc19d95550fd06c1cacd43fe165f80e3b80242f0c66a733",
            //"00000000008f8b37dc19d95550fd06c1cacd43fe165f80e3b80242f0c66a733",
        //本例中的一个公钥是（使用时去掉空格）：
            //@"F5AB4BCC 007AF4C3 862CF413 57C035AE 090B39B3 A7204E2D E888753E 99EC507A"
            //@"BE394FC1 0F50FC59 F6586DF7 B493150E 5DF7F575 BC1214FE D849E967 D15993FF"
        
        NSString *mingwen = @"123458";
        
        //因为miwen之前设置的是100所以运行后会崩溃，现在改成1024崩溃解除
        char miwen[1024];
        NSString *px_ = [@"F5AB4BCC 007AF4C3 862CF413 57C035AE 090B39B3 A7204E2D E888753E 99EC507A" stringByReplacingOccurrencesOfString:@" " withString:@""];
        NSString *py_ = [@"BE394FC1 0F50FC59 F6586DF7 B493150E 5DF7F575 BC1214FE D849E967 D15993FF" stringByReplacingOccurrencesOfString:@" " withString:@""];
        NSData *px_data = [self dataFromHexString:px_];
        NSData *py_data = [self dataFromHexString:py_];
        sm2JiaMiWithPublicKey(sm2_param_recommand, TYPE_GFp, 256, (char*)[mingwen UTF8String], miwen, px_data.bytes, py_data.bytes);
        //密文前面多个04  在用其他工具对密文解密时需要去掉
        NSData *miwendata = [[NSData alloc]initWithBytes:miwen length: mingwen.length+32+64 +2];
        NSLog(@"密文data=%@", miwendata );
        
        
        //解密和加密类似将char数组转成nsdata再转成nsstring
        //本工程的解密中使用的私钥是固定的：sm2_param_d_B[2]，如果需要手动传入私钥进行解密可以联系我
        char output[100];
        sm2Jiemi(sm2_param_recommand, TYPE_GFp, 256, miwen,output);
        NSString *mingwenout = [[NSString alloc]initWithCString:output encoding:NSUTF8StringEncoding];
        NSLog(@"---解密后%@---",mingwenout);
    
    
        UITextView *textView = [[UITextView alloc]initWithFrame:CGRectMake(0, button.frame.origin.y + 70, SCREEN_WIDTH_NEW, SCREEN_HEIGHT_NEW - button.frame.origin.y - button.frame.size.height)];
        textView.text = [NSString stringWithFormat:@"加密：\n明文是：%@\n公钥是px:%@ py:%@\n密文是%@",mingwen,px_,py_,miwendata];
        textView.text = [textView.text stringByAppendingFormat:@"\n\n解密：\n明文是：%@",mingwenout];
        
        [self.view addSubview:textView];
}
}
- (NSData *)dataFromHexString:(NSString *)input {
    const char *chars = [input UTF8String];
    int i = 0;
    NSUInteger len = input.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    return data;
}
@end
