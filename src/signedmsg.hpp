#ifndef SIGNEDMSG_HPP
#define SIGNEDMSG_HPP

#include <string>
#include <openssl/bn.h>

class SignedMsg {
public:
    std::string msg;
    BIGNUM *r, *s;

    SignedMsg() {};
    SignedMsg(const std::string, const BIGNUM*, const BIGNUM*);
    ~SignedMsg();

    int PrintSignedMsg();
};

int SignedMsg::PrintSignedMsg() {
    std::cout << "---------- Message info ----------------" << std::endl;

    std::cout << "Message: " << this->msg << std::endl;

    char *prt;
    prt = BN_bn2hex(this->r);
    std::cout << "r: " << prt << std::endl;

    prt = BN_bn2hex(this->s);
    std::cout << "s: " << prt << std::endl;

    return 1;
}

SignedMsg::SignedMsg(const std::string msg, const BIGNUM *r, const BIGNUM *s) {
    this->r = BN_new();
    this->s = BN_new();
    
    BIGNUM *zero = BN_new();
    BN_zero(zero);

    BN_add(this->r, r, zero);
    BN_add(this->s, s, zero);

    this->msg = msg;

}

SignedMsg::~SignedMsg() {
    BN_clear_free(this->r);
    BN_clear_free(this->s);
}

#endif
