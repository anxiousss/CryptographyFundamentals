#include "test_rijndael.hpp"
#include <iostream>

int main() {
    std::cout << "=========================================" << std::endl;
    std::cout << "   RIJNDAEL/AES TEST SUITE WITH POLYNOMIAL SELECTION" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "1. Run all tests with all polynomials" << std::endl;
    std::cout << "2. Run tests with polynomial selection" << std::endl;
    std::cout << "3. Run basic tests (no files)" << std::endl;
    std::cout << "4. Run file tests with default polynomial" << std::endl;
    std::cout << "=========================================\n" << std::endl;

    std::cout << "Choose option (1-4): ";
    int option;
    std::cin >> option;

    std::filesystem::path test_dir = "test_files";

    if (!std::filesystem::exists(test_dir)) {
        std::cout << "Note: Directory 'test_files/' not found." << std::endl;
        std::cout << "Creating directory for test files..." << std::endl;
        std::filesystem::create_directories(test_dir);
        std::cout << "Place your test files in 'test_files/' directory:" << std::endl;
        std::cout << "  - test.txt, test.bin, SMILEFACE.jpg, test.pdf, test.zip, test.mp4" << std::endl;

}