#!/usr/bin/env python3
"""
Binary to C Array Converter

This script reads a binary file and generates a C header file containing
a uint8_t array with the binary data.

Usage:
    python bin_to_array.py <input_binary_file_good> <input_binary_file_bad> <output_c_file>

Example:
    python bin_to_array.py myfile_good.bin myfile_bad.bin myfile.h
"""

import sys

def main():
    if len(sys.argv) != 4:
        print("Usage: python bin_to_array.py <input_binary_file_good> <input_binary_file_bad> <output_c_file>")
        sys.exit(1)

    input_file_good = sys.argv[1]
    input_file_bad = sys.argv[2]
    output_file = sys.argv[3]

    # Read binary data
    with open(input_file_good, 'rb') as f:
        data_good = f.read()

    with open(input_file_bad, 'rb') as f:
        data_bad = f.read()

    if len(data_good) != len(data_bad):
        print("Error: Input files must be of the same length.")
        sys.exit(1)

    # Generate C array
    with open(output_file, 'w') as f:

        def write_data(data):
            ret = ''
            # Write data in hex format, 16 bytes per line
            for i in range(0, len(data), 16):
                ret += '  ' + ''.join([f"0x{byte:02x}," for byte in data[i:i+16]]) + '\n'
            return ret

        f.write(f'''\
// Generated Shellcode.
// See ./scripts/generate_hack.sh for details.
#define ATTACK_USER_PREF_SIZE {len(data_good)}
static const uint8_t ATTACK_BAD_USER_PREFERENCES[ATTACK_USER_PREF_SIZE] = {{
{write_data(data_bad)}}};

static const uint8_t ATTACK_GOOD_USER_PREFERENCES[ATTACK_USER_PREF_SIZE] = {{
{write_data(data_good)}}};
''')


if __name__ == "__main__":
    main()
