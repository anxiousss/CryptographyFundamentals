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
}