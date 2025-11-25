#include "test_rsa.hpp"
#include <iostream>

int main() {
    std::cout << "RSA File Encryption Test Suite" << std::endl;
    std::cout << "==============================" << std::endl;

    try {
        SimpleRSATests tests;
        bool success = tests.run_all_tests();

        if (success) {
            std::cout << "\n All tests completed successfully!" << std::endl;
            return 0;
        } else {
            std::cout << "\n Some tests failed!" << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 2;
    }

    /*std::cout << rsa::Wieners_attack(1073780833, 1220275921) << std::endl;
    std::cout << rsa::Wieners_attack(1779399043, 2796304957) << std::endl;

    auto pub = rsa::RsaKeysGeneration(rsa::TestTypes::MilerRabinTest, 0.9, 512).generate_bad_keys().first;
    std::cout << pub.first << ' ' << pub.second << std::endl;
    std::cout << rsa::Wieners_attack(pub.first, pub.second);*/
    return 0;
}