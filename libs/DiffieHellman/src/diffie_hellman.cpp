#include "diffie_hellman.hpp"

namespace diffie_hellman {

    std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>
    Protocol::generate_parameters(size_t key_length){
        boost::multiprecision::cpp_int g = 2;

        boost::random::random_device rand_device;
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int>
                dist(boost::multiprecision::cpp_int(1) << (key_length - 1),
                     (boost::multiprecision::cpp_int(1) << key_length) - 1);
        primality_tests::MillerRabinPrimalityTest primality_test;

        boost::multiprecision::cpp_int p;

       do {
           p = dist(rand_device);
       } while (primality_test.is_prime(p, 0.999) < 0.999);


       return {g, p};
    }

    Protocol::AliceKeys Protocol::generate_alice_keys(size_t key_length) {
        auto [g, p] = generate_parameters(key_length);

        boost::random::random_device rand_device;
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist_a(2, p - 2);

        boost::multiprecision::cpp_int a = dist_a(rand_device);
        boost::multiprecision::cpp_int A = number_functions::NumberTheoryFunctions::mod_exp(g, a, p);

        return AliceKeys(g, p, A, a);
    }

    Protocol::BobKeys Protocol::generate_bob_keys(const boost::multiprecision::cpp_int& g, const boost::multiprecision::cpp_int& p) {
        boost::random::random_device rand_device;
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist_b(2, p - 2);

        boost::multiprecision::cpp_int b = dist_b(rand_device);
        boost::multiprecision::cpp_int B = number_functions::NumberTheoryFunctions::mod_exp(g, b, p);

        return BobKeys(B, b);
    }

     boost::multiprecision::cpp_int Protocol::compute_secret_key_alice(const boost::multiprecision::cpp_int& B,
                                                             const boost::multiprecision::cpp_int& a,
                                                             const boost::multiprecision::cpp_int& p) {

        return number_functions::NumberTheoryFunctions::mod_exp(B, a, p);
    }

     boost::multiprecision::cpp_int Protocol::compute_secret_key_bob(const boost::multiprecision::cpp_int& A,
                                                           const boost::multiprecision::cpp_int& b,
                                                           const boost::multiprecision::cpp_int& p) {

        return number_functions::NumberTheoryFunctions::mod_exp(A, b, p);
    }

}