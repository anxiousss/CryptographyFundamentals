#include <vector>
#include <cstddef>

namespace galois_fields {

    class GaloisField {
    private:
        GaloisField add(const GaloisField& other) const;
        GaloisField multiply(const GaloisField& other) const;
        GaloisField multiplicative_inverse(const GaloisField& other) const;
    public:
        std::vector<std::byte> element;
        GaloisField operator+(const GaloisField& other) const;
        GaloisField operator*(const GaloisField& other) const;
        std::vector<std::byte> find_irreducible_polynomials() const;
    };
}