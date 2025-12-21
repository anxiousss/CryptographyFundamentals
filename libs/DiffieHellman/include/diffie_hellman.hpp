#include <boost/multiprecision/cpp_int.hpp>
#include "primality_tests.hpp"

namespace diffie_hellman {

    class Protocol {
    public:
        struct AliceKeys {
        public:
            boost::multiprecision::cpp_int g;
            boost::multiprecision::cpp_int p;
            boost::multiprecision::cpp_int A;

            AliceKeys(const boost::multiprecision::cpp_int& g_val,
                      const boost::multiprecision::cpp_int& p_val,
                      const boost::multiprecision::cpp_int& A_val,
                      const boost::multiprecision::cpp_int& a_val)
                    : g(g_val), p(p_val), A(A_val), a(a_val) {}

            boost::multiprecision::cpp_int get_a() {return a;}

        private:
            boost::multiprecision::cpp_int a;
        };

        struct BobKeys {
        public:
            boost::multiprecision::cpp_int B;

            BobKeys(const boost::multiprecision::cpp_int& B_val,
                    const boost::multiprecision::cpp_int& b_val)
                    : B(B_val), b(b_val) {}


            boost::multiprecision::cpp_int get_b() {return b;}

        private:
            boost::multiprecision::cpp_int b;
        };

        static std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>
        generate_parameters(size_t key_length);

        static AliceKeys generate_alice_keys(size_t key_length);

        static BobKeys
        generate_bob_keys(const boost::multiprecision::cpp_int &g, const boost::multiprecision::cpp_int &p);

        static boost::multiprecision::cpp_int compute_secret_key_alice(const boost::multiprecision::cpp_int &B,
                                                                       const boost::multiprecision::cpp_int &a,
                                                                       const boost::multiprecision::cpp_int &p);

        static boost::multiprecision::cpp_int compute_secret_key_bob(const boost::multiprecision::cpp_int &A,
                                                                     const boost::multiprecision::cpp_int &b,
                                                                     const boost::multiprecision::cpp_int &p);
    };
}