#ifndef DSA_HPP
#define DSA_HPP

#include <iostream>
#include <string>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include "signedmsg.hpp"

#define J 8

class MyDSA {
public:
    // allocate big numbers
    // DSA 公钥及公开元素
    BIGNUM *p, *q, *g, *y, *h;
    // OpenSSL 库中的错误处理机制，不用管……
    BN_CTX *ctx;

    MyDSA();
    ~MyDSA();
    SignedMsg * Signature(const std::string);
    int Verification(const SignedMsg *);
    int PrintMyDSAInfo();

private:
    // DSA 私钥
    BIGNUM *x;

};

int MyDSA::PrintMyDSAInfo() {

    std::cout << "---------- My DSA info ----------------" << std::endl;

    char *prt;
    prt = BN_bn2hex(this->p);
    std::cout << "p: " << prt << std::endl;

    prt = BN_bn2hex(this->q);
    std::cout << "q: " << prt << std::endl;

    prt = BN_bn2hex(this->g);
    std::cout << "g: " << prt << std::endl;

    prt = BN_bn2hex(this->x);
    std::cout << "x: " << prt << std::endl;

    prt = BN_bn2hex(this->y);
    std::cout << "y: " << prt << std::endl;

    return 1;
}

int MyDSA::Verification(const SignedMsg *signedMsg) {
    BIGNUM *omega = BN_new();
    BIGNUM *u1 = BN_new();
    BIGNUM *u2 = BN_new();

    // omega = s^-1 mod q
    BIGNUM *s_inverse = BN_new();
    BN_mod_inverse(s_inverse, signedMsg->s, this->q, this->ctx);

    BN_mod(omega, s_inverse, this->q, this->ctx);

    // u1 = (H(m) omega) mod q
        // H(m)
    BIGNUM *digest = BN_new();
    const char* msg_char = signedMsg->msg.c_str();
    unsigned char *digest_char = SHA1((const unsigned char*)msg_char, signedMsg->msg.length(), NULL); // not thread safe
    BN_bin2bn(digest_char, 20, digest);

    BN_mod_mul(u1, digest, omega, this->q, this->ctx);

    // u2 = r omega mod q
    BN_mod_mul(u2, signedMsg->r, omega, this->q, this->ctx);

    // compare
    BIGNUM *re_cal = BN_new();
    
    BIGNUM *g_u1 = BN_new();
    BIGNUM *y_u2 = BN_new();
    // 求 g^u1 和 y^u2，直接 exp 量级过于庞大（L**160 的量级），因此先 mod p 缩小量级再进行计算，否则无法在多项式时间内得出结果。
    // BN_exp(g_u1, this->g, u1, this->ctx);
    // BN_exp(y_u2, this->y, u2, this->ctx);
    BN_mod_exp(g_u1, this->g, u1, this->p, this->ctx);
    BN_mod_exp(y_u2, this->y, u2, this->p, this->ctx);

    BIGNUM *gu1_mul_yu2_mod_p = BN_new();
    BN_mod_mul(gu1_mul_yu2_mod_p, g_u1, y_u2, this->p, this->ctx);
    
    BN_mod(re_cal, gu1_mul_yu2_mod_p, this->q, this->ctx);

    // 比较计算结果和信息中所带签名信息，若相同即为认证。
    if (BN_cmp(re_cal, signedMsg->r) == 0) {
        // std::cout << "[✓][Verified] " << signedMsg->msg << std::endl;
        return 1;
    } else {
        // std::cout << "[!][Unverified] " << signedMsg->msg << std::endl;
        return 0;
    }
    
    return -1;

}


SignedMsg * MyDSA::Signature(const std::string msg) {
    // k
    BIGNUM *k = BN_new();
    do {
        BN_rand_range(k, this->q);
    } while(BN_is_zero(k));

    // r = (g^k mod p) mod q
    BIGNUM *r = BN_new();
    BIGNUM *g_k_mod_p = BN_new();
    BN_mod_exp(g_k_mod_p, this->g, k, this->p, this->ctx);
    BN_mod(r, g_k_mod_p, this->q, this->ctx);

    // s = (k^-1 (H(m) + xr)) mod q
    BIGNUM *s = BN_new();
    BIGNUM *k_inverse = BN_new();
    BN_mod_inverse(k_inverse, k, this->q, this->ctx);
        // H(m)
    BIGNUM *digest = BN_new();
    const char* msg_char = msg.c_str();
    // 消息使用 SHA1 获取摘要
    unsigned char *digest_char = SHA1((const unsigned char*)msg_char, msg.length(), NULL); // not thread safe
    BN_bin2bn(digest_char, 20, digest);

    char *pt_digest = BN_bn2hex(digest);
    std::cout << "SHA1 Digest: " << pt_digest << std::endl;

        // xr
    BIGNUM *xr = BN_new();
    BN_mul(xr, this->x, r, this->ctx);
        // H(m) + xr
    BN_add(digest, digest, xr);

    BN_mod_mul(s, k_inverse, digest, this->q, this->ctx);

    SignedMsg *signedMsg = new SignedMsg(msg, r, s);

    return signedMsg;

}

MyDSA::MyDSA() {
    // allocate big numbers
    this->p = BN_new();
    this->q = BN_new();
    this->g = BN_new();
    this->y = BN_new();
    this->x = BN_new();
    this->h = BN_new();

    this->ctx = BN_CTX_new();

    BIGNUM *one = BN_new();
    BN_one(one);

    // 生成 p, q, g, x, y。
    // p 和 q 之间的关系比较特殊，需要满足 p % q == 1 。且 p 和 q 都为素数。
    // 其实这个要自己生成时有点复杂的，好在 OpenSSL 提供了这个功能。
    // q
    BN_generate_prime_ex(this->q, 160, true, NULL, NULL, NULL);
    // p
    BN_generate_prime_ex(this->p, 512+J*8, false, this->q, one, NULL);

    // g = h^((p-1)/q) mod p
    BIGNUM *p_minus_1 = BN_new();
    BN_sub(p_minus_1, this->p, one);
    do {
        BN_rand_range(this->h, p_minus_1);
    } while (BN_is_zero(this->h) || BN_is_one(this->h));

    BIGNUM *p_minus_1_div_q = BN_new();
    BN_div(p_minus_1_div_q, NULL, p_minus_1, q, this->ctx);

    BN_mod_exp(this->g, this->h, p_minus_1_div_q, this->p, this->ctx);

    // x
    do {
        BN_rand_range(this->x, this->q);
    } while (BN_is_zero(this->x));

    // y = g^x mod p
    BN_mod_exp(this->y, this->g, this->x, this->p, this->ctx);

}

MyDSA::~MyDSA() {
    // 清除分配的大数占用的内存空间，防止内存泄露。
    BN_clear_free(this->p);
    BN_clear_free(this->q);
    BN_clear_free(this->g);
    BN_clear_free(this->y);
    BN_clear_free(this->x);
    BN_clear_free(this->h);
    
    BN_CTX_free(this->ctx);

    // std::cout << "Clean is done, Goodbye ~" << std::endl;
}

#endif
