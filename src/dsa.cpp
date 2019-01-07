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

#include "dsa.hpp"

int main() {
    
    // 初始化 DSA
    MyDSA dsa;
    dsa.PrintMyDSAInfo();

    // 待签名信息
    // std::string msg = "Hello, TripleZ !";
    std::string msg = "小布丁天下第一！";

    SignedMsg *signedMsg;

    // 对信息使用 DSA 进行签名。
    signedMsg = dsa.Signature(msg);
    signedMsg->PrintSignedMsg();

    // 使用 DSA 公开信息验证签名（成功）
    int verified = -1;
    verified = dsa.Verification(signedMsg);

    std::cout << "---------- Verification info ----------------" << std::endl;

    switch (verified) {
    case -1:
        std::cout << "UNKNOWN ERROR" << std::endl;
        break;
    case 1:
        std::cout << "[✓][Verified] " << signedMsg->msg << std::endl;
        break;
    case 0:
        std::cout << "[!][Unverified] " << signedMsg->msg << std::endl;
        break;
    }

    // 模拟黑客更改信息
    // simulate hacker modified the signed message
    signedMsg->msg = "TripleZ 天下第一！";
    signedMsg->PrintSignedMsg();
    // 使用 DSA 公开信息验证签名（失败）
    verified = dsa.Verification(signedMsg);

    std::cout << "---------- Verification info ----------------" << std::endl;

    switch (verified) {
    case -1:
        std::cout << "UNKNOWN ERROR" << std::endl;
        break;
    case 1:
        std::cout << "[✓][Verified] " << signedMsg->msg << std::endl;
        break;
    case 0:
        std::cout << "[!][Unverified] " << signedMsg->msg << std::endl;
        break;
    }

    // 清除分配的堆空间
    delete signedMsg;

    return 0;
}


