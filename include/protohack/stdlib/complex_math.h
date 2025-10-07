#ifndef PROTOHACK_STDLIB_COMPLEX_MATH_H
#define PROTOHACK_STDLIB_COMPLEX_MATH_H

#include <stdbool.h>

#include "protohack/error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double real;
    double imag;
} ProtoStdComplex;

ProtoStdComplex proto_stdlib_complex_add(ProtoStdComplex lhs, ProtoStdComplex rhs);
ProtoStdComplex proto_stdlib_complex_sub(ProtoStdComplex lhs, ProtoStdComplex rhs);
ProtoStdComplex proto_stdlib_complex_mul(ProtoStdComplex lhs, ProtoStdComplex rhs);
ProtoStdComplex proto_stdlib_complex_div(ProtoStdComplex lhs, ProtoStdComplex rhs, ProtoError *error);
double proto_stdlib_complex_abs(ProtoStdComplex value);
ProtoStdComplex proto_stdlib_complex_exp(ProtoStdComplex value);

#ifdef __cplusplus
}
#endif

#endif
