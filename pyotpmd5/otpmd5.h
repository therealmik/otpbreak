#include <stdint.h>

int64_t _otpmd5(int64_t input, int rounds);
void _otpmd5_chain(int64_t* result, int64_t input, unsigned int rounds);


