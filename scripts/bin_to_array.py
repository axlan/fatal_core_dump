#!/usr/bin/env python3
"""
Binary to C Array Converter

This script reads a binary file and generates a C header file containing
a uint8_t array with the binary data.

Usage:
    python bin_to_array.py <input_binary_file> <output_c_file>

Example:
    python bin_to_array.py myfile.bin myfile.h
"""

import sys
import os


def main():
    if len(sys.argv) != 3:
        print("Usage: python bin_to_array.py <input_binary_file> <output_c_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Check if input file exists
    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    # Read binary data
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    # Generate C array
    # Write array declaration
    array_name = os.path.splitext(os.path.basename(input_file))[0].replace('-', '_').replace('.', '_')

    try:
        with open(output_file, 'w') as f:
            f.write(f'''\
// Generated Shellcode.
// See ./scripts/generate_hack.sh for details.
#define ATTACK_USER_PREF_SIZE {len(data)}
static const uint8_t ATTACK_USER_PREFERENCES[ATTACK_USER_PREF_SIZE] = {{
''')

            # Write data in hex format, 16 bytes per line
            for i in range(0, len(data), 16):
                f.write('  ' + ''.join([f"0x{byte:02x}," for byte in data[i:i+16]]) + '\n')

            f.write("};\n")
    except IOError as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
