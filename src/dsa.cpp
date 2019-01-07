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

    // 模仿黑客更改信息
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


