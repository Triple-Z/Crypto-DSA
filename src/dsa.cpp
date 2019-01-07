#include "dsa.hpp"

int main() {
    
    MyDSA dsa;
    dsa.PrintMyDSAInfo();

    std::string msg = "Hello, TripleZ !";

    SignedMsg *signedMsg;

    signedMsg = dsa.Signature(msg);
    signedMsg->PrintSignedMsg();

    int verified = dsa.Verification(signedMsg);

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

    delete signedMsg;

    return 0;
}


