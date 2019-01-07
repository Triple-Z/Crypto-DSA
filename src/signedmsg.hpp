// Copyright (c) 2019 Zhenzhen Zhao<me@triplez.cn>
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef SIGNEDMSG_HPP
#define SIGNEDMSG_HPP

#include <string>
#include <openssl/bn.h>

class SignedMsg {
    // 签名消息类，就用于结构化签名消息内容。分别是消息 msg，签名信息 r 和 s。
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
