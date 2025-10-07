#include "protohack/stdlib/complex_math.h"

#include <cmath>
#include <complex>

namespace {

static std::complex<double> to_std_complex(ProtoStdComplex value) {
    return {value.real, value.imag};
}

static ProtoStdComplex from_std_complex(const std::complex<double> &value) {
    return {value.real(), value.imag()};
}

} // namespace

extern "C" ProtoStdComplex proto_stdlib_complex_add(ProtoStdComplex lhs, ProtoStdComplex rhs) {
    return from_std_complex(to_std_complex(lhs) + to_std_complex(rhs));
}

extern "C" ProtoStdComplex proto_stdlib_complex_sub(ProtoStdComplex lhs, ProtoStdComplex rhs) {
    return from_std_complex(to_std_complex(lhs) - to_std_complex(rhs));
}

extern "C" ProtoStdComplex proto_stdlib_complex_mul(ProtoStdComplex lhs, ProtoStdComplex rhs) {
    return from_std_complex(to_std_complex(lhs) * to_std_complex(rhs));
}

extern "C" ProtoStdComplex proto_stdlib_complex_div(ProtoStdComplex lhs, ProtoStdComplex rhs, ProtoError *error) {
    if (error) {
        protoerror_reset(error);
    }

    const std::complex<double> denominator = to_std_complex(rhs);
    if (std::abs(denominator) == 0.0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "Complex division by zero");
        }
        return {0.0, 0.0};
    }
    return from_std_complex(to_std_complex(lhs) / denominator);
}

extern "C" double proto_stdlib_complex_abs(ProtoStdComplex value) {
    return std::abs(to_std_complex(value));
}

extern "C" ProtoStdComplex proto_stdlib_complex_exp(ProtoStdComplex value) {
    return from_std_complex(std::exp(to_std_complex(value)));
}
