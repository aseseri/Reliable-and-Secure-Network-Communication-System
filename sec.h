#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void init_sec(int initial_state);

// Get input from security layer
ssize_t input_sec(uint8_t* buf, size_t max_length);
// fill the buffer with what you want to send in the proper TLV format

// Output to security layer
void output_sec(uint8_t* buf, size_t length);
// receive such a buffer in the TLV format and must reverse engineer its contents

// Get input (no security layer)
ssize_t input_no_sec(uint8_t* buf, size_t max_length);

// Output (no security layer)
void output_no_sec(uint8_t* buf, size_t length);