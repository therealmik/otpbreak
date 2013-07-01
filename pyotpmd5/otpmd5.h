#include <stdint.h>

uint64_t _otpmd5(uint64_t* input, int rounds);
void _otpmd5_chain(uint64_t* result, uint64_t* input, int rounds);


