#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <boost/multiprecision/cpp_int.hpp>
#include "primality_tests.hpp"

using namespace primality_tests;
using namespace boost::multiprecision;
using namespace std;

class SimpleTestRunner {
private:
    int passed = 0;
    int failed = 0;
    vector<string> failures;

    void printResult(const string& testName, bool success) {
       if (success) {
          cout << "✓ " << testName << " PASSED" << endl;
          passed++;
       } else {
          cout << "✗ " << testName << " FAILED" << endl;
          failed++;
       }
    }

    bool withinTolerance(double a) {
       return abs(a - 0.984375) < 0.01;
    }

public:
    void runFermatTests() {
       cout << "\n=== Fermat Primality Test ===" << endl;
       FermatPrimalityTest test;

       // Small primes
       printResult("Fermat - Small prime 2",
                   test.is_prime(cpp_int(2), 0.99) >= 0.99);
       printResult("Fermat - Small prime 3",
                   test.is_prime(cpp_int(3), 0.99) >= 0.99);
       printResult("Fermat - Small prime 13",
                   test.is_prime(cpp_int(13), 0.99) >= 0.99);

       // Small composites
       printResult("Fermat - Composite 4",
                   test.is_prime(cpp_int(4), 0.99) == 0.0);
       printResult("Fermat - Composite 15",
                   test.is_prime(cpp_int(15), 0.99) == 0.0);

       // Larger numbers
       printResult("Fermat - Large prime 1009",
                   test.is_prime(cpp_int(1009), 0.99) >= 0.99);
       printResult("Fermat - Large composite 1001",
                   test.is_prime(cpp_int(1001), 0.99) == 0.0);

    }

    void runSolovayStrassenTests() {
       cout << "\n=== Solovay-Strassen Primality Test ===" << endl;
       SolovayStrassenPrimalityTest test;

       // Small primes
       printResult("Solovay-Strassen - Small prime 5",
                   test.is_prime(cpp_int(5), 0.99) >= 0.99);
       printResult("Solovay-Strassen - Small prime 17",
                   test.is_prime(cpp_int(17), 0.99) >= 0.99);

       // Small composites
       printResult("Solovay-Strassen - Composite 9",
                   test.is_prime(cpp_int(9), 0.99) == 0.0);
       printResult("Solovay-Strassen - Composite 25",
                   test.is_prime(cpp_int(25), 0.99) == 0.0);

       // Carmichael number (should be detected as composite)
       printResult("Solovay-Strassen - Carmichael 561",
                   test.is_prime(cpp_int(561), 0.99) == 0.0);
    }

    void runMillerRabinTests() {
       cout << "\n=== Miller-Rabin Primality Test ===" << endl;
       MillerRabinPrimalityTest test;

       // Small primes
       printResult("Miller-Rabin - Small prime 7",
                   test.is_prime(cpp_int(7), 0.99) >= 0.99);
       printResult("Miller-Rabin - Small prime 19",
                   test.is_prime(cpp_int(19), 0.99) >= 0.99);

       // Small composites
       printResult("Miller-Rabin - Composite 21",
                   test.is_prime(cpp_int(21), 0.99) == 0.0);
       printResult("Miller-Rabin - Composite 27",
                   test.is_prime(cpp_int(27), 0.99) == 0.0);

       // Larger primes
       printResult("Miller-Rabin - Large prime 7919",
                   test.is_prime(cpp_int(7919), 0.99) >= 0.99);

       // Probability calculations
       printResult("Miller-Rabin - Probability calculation",
                   withinTolerance(test.prime_probability(3)));
       printResult("Miller-Rabin - Iterations calculation",
                   test.n_iterations(0.9) == 2);
    }

    void runEdgeCaseTests() {
       cout << "\n=== Edge Case Tests ===" << endl;
       FermatPrimalityTest test;

       // Very small numbers
       printResult("Edge - Number 0",
                   test.is_prime(cpp_int(0), 0.99) == 0.0);
       printResult("Edge - Number 1",
                   test.is_prime(cpp_int(1), 0.99) == 0.0);

       // Even numbers (except 2)
       printResult("Edge - Even number 4",
                   test.is_prime(cpp_int(4), 0.99) == 0.0);
       printResult("Edge - Even number 100",
                   test.is_prime(cpp_int(100), 0.99) == 0.0);
    }

    void runPerformanceTests() {
       cout << "\n=== Performance Tests ===" << endl;
       MillerRabinPrimalityTest test;

       vector<cpp_int> test_primes = {
               cpp_int(1009),
               cpp_int(7919),
               cpp_int(65537),
               cpp_int("10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000557")
       };

       for (size_t i = 0; i < test_primes.size(); ++i) {
          auto start = chrono::high_resolution_clock::now();
          double result = test.is_prime(test_primes[i], 0.99);
          auto end = chrono::high_resolution_clock::now();
          auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);

          bool success = result >= 0.99;
          string testName = "Performance test prime " + to_string(i + 1) +
                            " (" + to_string(duration.count()) + "ms)";
          printResult(testName, success);

          if (duration.count() > 5000) { // 5 seconds
             cout << "  WARNING: Test took longer than 5 seconds" << endl;
          }
       }
    }

    void runComparativeTests() {
       cout << "\n=== Comparative Tests ===" << endl;
       FermatPrimalityTest fermat;
       SolovayStrassenPrimalityTest solovay;
       MillerRabinPrimalityTest miller;

       vector<cpp_int> primes = {cpp_int(5), cpp_int(17), cpp_int(1009)};
       vector<cpp_int> composites = {cpp_int(9), cpp_int(25), cpp_int(1001)};

       // Test that all algorithms agree on primes
       for (const auto& p : primes) {
          bool fermat_ok = fermat.is_prime(p, 0.99) >= 0.99;
          bool solovay_ok = solovay.is_prime(p, 0.99) >= 0.99;
          bool miller_ok = miller.is_prime(p, 0.99) >= 0.99;

          bool all_agree = fermat_ok && solovay_ok && miller_ok;
          printResult("Comparative - All agree on prime " + p.str(), all_agree);
       }

       // Test that all algorithms agree on composites
       for (const auto& c : composites) {
          bool fermat_ok = fermat.is_prime(c, 0.99) == 0.0;
          bool solovay_ok = solovay.is_prime(c, 0.99) == 0.0;
          bool miller_ok = miller.is_prime(c, 0.99) == 0.0;

          bool all_agree = fermat_ok && solovay_ok && miller_ok;
          printResult("Comparative - All agree on composite " + c.str(), all_agree);
       }
    }

    void runErrorCaseTests() {
       cout << "\n=== Error Case Tests ===" << endl;
       FermatPrimalityTest test;

       try {
          test.is_prime(cpp_int(5), 0.4); // Probability too low
          printResult("Error - Low probability exception", false);
       } catch (const invalid_argument&) {
          printResult("Error - Low probability exception", true);
       } catch (...) {
          printResult("Error - Low probability exception", false);
       }

       try {
          test.is_prime(cpp_int(5), 1.1); // Probability too high
          printResult("Error - High probability exception", false);
       } catch (const invalid_argument&) {
          printResult("Error - High probability exception", true);
       } catch (...) {
          printResult("Error - High probability exception", false);
       }
    }

    void runAllTests() {
       cout << "Running Primality Tests..." << endl;
       cout << "============================" << endl;

       auto start_time = chrono::high_resolution_clock::now();

       runFermatTests();
       runSolovayStrassenTests();
       runMillerRabinTests();
       runEdgeCaseTests();
       runComparativeTests();
       runErrorCaseTests();
       runPerformanceTests();

       auto end_time = chrono::high_resolution_clock::now();
       auto total_duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

       // Summary
       cout << "\n=== TEST SUMMARY ===" << endl;
       cout << "Total tests: " << (passed + failed) << endl;
       cout << "Passed: " << passed << endl;
       cout << "Failed: " << failed << endl;
       cout << "Success rate: " << (passed * 100.0 / (passed + failed)) << "%" << endl;
       cout << "Total time: " << total_duration.count() << "ms" << endl;

       if (failed == 0) {
          cout << "\n ALL TESTS PASSED! 🎉" << endl;
       } else {
          cout << "\n SOME TESTS FAILED!" << endl;
          cout << "Failed tests:" << endl;
          for (const auto& failure : failures) {
             cout << "  - " << failure << endl;
          }
       }
    }
};

int main() {
   SimpleTestRunner runner;
   runner.runAllTests();
   return 0;
}
