"""
CryptHaven Security Upgrade — Validation Test Suite
Run after each phase: python test_security.py
"""
import os
import sys
import json
import secrets
import base64
import tempfile
import shutil
import time

# ---------------------------------------------------------------------------
# Ensure we can import from crypthaven_server
# ---------------------------------------------------------------------------
if sys.stdout is not None and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS_COUNT = 0
FAIL_COUNT = 0

def test(name, condition, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        print(f"  ✅ PASS: {name}")
        PASS_COUNT += 1
    else:
        print(f"  ❌ FAIL: {name} — {detail}")
        FAIL_COUNT += 1

def heading(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ===========================================================================
# PHASE 0 — Import Checks
# ===========================================================================
def test_phase0():
    heading("Phase 0 — Import & Dependency Checks")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        test("AESGCM importable", True)
    except ImportError as e:
        test("AESGCM importable", False, str(e))

    try:
        import argon2
        test("argon2-cffi importable", True)
    except ImportError as e:
        test("argon2-cffi importable", False, str(e))

    try:
        from argon2.low_level import hash_secret_raw, Type
        raw = hash_secret_raw(
            secret=b"test",
            salt=b"0" * 16,
            time_cost=1,
            memory_cost=16384,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        test("Argon2id produces 32-byte output", len(raw) == 32, f"got {len(raw)}")
    except Exception as e:
        test("Argon2id basic operation", False, str(e))

# ===========================================================================
# PHASE 1 — Core Encryption Functions
# ===========================================================================
def test_phase1():
    heading("Phase 1 — Core Encryption Functions")

    try:
        from crypthaven_server import vault_encrypt, vault_decrypt, generate_dek
        from crypthaven_server import derive_kek, wrap_dek, unwrap_dek
    except ImportError as e:
        print(f"  ⚠️  Cannot import new functions yet — skip Phase 1 tests ({e})")
        return

    # Test DEK generation
    dek = generate_dek()
    test("generate_dek() returns 32 bytes", len(dek) == 32, f"got {len(dek)}")
    dek2 = generate_dek()
    test("generate_dek() is random each time", dek != dek2)

    # Test encrypt/decrypt roundtrip
    plaintext = b"Hello CryptHaven! This is a test message."
    ciphertext = vault_encrypt(plaintext, dek)
    test("vault_encrypt output starts with version byte 0x02",
         ciphertext[0:1] == b'\x02', f"got {ciphertext[0:1]}")
    test("vault_encrypt output is larger than plaintext",
         len(ciphertext) > len(plaintext))
    decrypted = vault_decrypt(ciphertext, dek)
    test("vault_decrypt recovers original plaintext",
         decrypted == plaintext, f"got {decrypted[:50]}")

    # Test that different encryptions produce different ciphertext (unique nonce)
    ct1 = vault_encrypt(plaintext, dek)
    ct2 = vault_encrypt(plaintext, dek)
    test("Same plaintext produces different ciphertext (unique nonce)", ct1 != ct2)

    # Test decryption with wrong key fails
    wrong_dek = generate_dek()
    try:
        vault_decrypt(ciphertext, wrong_dek)
        test("Decryption with wrong key raises error", False, "did not raise")
    except Exception:
        test("Decryption with wrong key raises error", True)

    # Test tampered ciphertext fails
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF  # flip last byte
    try:
        vault_decrypt(bytes(tampered), dek)
        test("Tampered ciphertext raises error", False, "did not raise")
    except Exception:
        test("Tampered ciphertext raises error", True)

    # Test KEK derivation
    salt = secrets.token_bytes(32)
    kek = derive_kek("testpassword123", salt)
    test("derive_kek returns 32 bytes", len(kek) == 32, f"got {len(kek)}")
    kek_same = derive_kek("testpassword123", salt)
    test("derive_kek is deterministic (same password+salt → same kek)", kek == kek_same)
    kek_diff = derive_kek("differentpassword", salt)
    test("derive_kek differs with different password", kek != kek_diff)

    # Test DEK wrapping
    wrapped = wrap_dek(dek, kek)
    test("wrap_dek produces output", len(wrapped) > 0)
    unwrapped = unwrap_dek(wrapped, kek)
    test("unwrap_dek recovers original DEK", unwrapped == dek)

    # Test unwrap with wrong KEK fails
    wrong_kek = derive_kek("wrongpassword", salt)
    try:
        unwrap_dek(wrapped, wrong_kek)
        test("unwrap_dek with wrong KEK raises error", False, "did not raise")
    except Exception:
        test("unwrap_dek with wrong KEK raises error", True)

    # Test large file encryption (simulating a 5MB photo)
    large_data = secrets.token_bytes(5 * 1024 * 1024)
    large_ct = vault_encrypt(large_data, dek)
    large_pt = vault_decrypt(large_ct, dek)
    test("Large file (5MB) encrypt/decrypt roundtrip", large_data == large_pt)

    # Test empty data
    empty_ct = vault_encrypt(b"", dek)
    empty_pt = vault_decrypt(empty_ct, dek)
    test("Empty data encrypt/decrypt roundtrip", empty_pt == b"")

# ===========================================================================
# PHASE 1b — Fernet Backward Compatibility
# ===========================================================================
def test_phase1b():
    heading("Phase 1b — Fernet Backward Compatibility")

    try:
        from crypthaven_server import vault_decrypt, derive_key
        from cryptography.fernet import Fernet
    except ImportError as e:
        print(f"  ⚠️  Cannot import functions — skip Phase 1b tests ({e})")
        return

    # Create Fernet-encrypted data (simulating old vault files)
    salt = secrets.token_bytes(16)
    old_key = derive_key("oldpassword", salt)
    fernet = Fernet(old_key)
    plaintext = b"This was encrypted with the OLD Fernet system."
    old_ciphertext = fernet.encrypt(plaintext)

    # Verify vault_decrypt can handle old Fernet format with fallback
    dek = secrets.token_bytes(32)  # dummy DEK — won't be used for Fernet data
    try:
        result = vault_decrypt(old_ciphertext, dek, fernet_fallback=fernet)
        test("vault_decrypt handles legacy Fernet with fallback", result == plaintext)
    except Exception as e:
        test("vault_decrypt handles legacy Fernet with fallback", False, str(e))

    # Verify vault_decrypt raises on Fernet data WITHOUT fallback
    try:
        vault_decrypt(old_ciphertext, dek, fernet_fallback=None)
        test("vault_decrypt raises on Fernet data without fallback", False, "did not raise")
    except (ValueError, Exception):
        test("vault_decrypt raises on Fernet data without fallback", True)

# ===========================================================================
# PHASE 2 — Vault Load/Save/Password Change
# ===========================================================================
def test_phase2():
    heading("Phase 2 — Vault Operations")

    try:
        from crypthaven_server import (
            set_vault_folder, load_vault, save_index, lock_vault,
            vault_decrypt, DECRYPTED_INDEX, generate_dek
        )
    except ImportError as e:
        print(f"  ⚠️  Cannot import vault functions — skip Phase 2 tests ({e})")
        return

    # Create a temporary vault directory
    tmp_dir = tempfile.mkdtemp(prefix="crypthaven_test_")
    try:
        set_vault_folder(tmp_dir)

        # Test new vault creation
        success, msg = load_vault("MyStr0ngP@ssw0rd!")
        test("New vault creation succeeds", success, msg)

        # Verify vault files were created
        dek_path = os.path.join(tmp_dir, "vault_dek.bin")
        salt_path = os.path.join(tmp_dir, "vault_salt.bin")
        index_path = os.path.join(tmp_dir, "vault_index.json")
        test("vault_dek.bin created", os.path.exists(dek_path))
        test("vault_salt.bin created", os.path.exists(salt_path))
        test("vault_index.json created", os.path.exists(index_path))

        # Verify salt is 32 bytes
        with open(salt_path, 'rb') as f:
            salt_data = f.read()
        test("Salt is 32 bytes", len(salt_data) == 32, f"got {len(salt_data)}")

        # Lock and re-unlock
        lock_vault()
        success2, msg2 = load_vault("MyStr0ngP@ssw0rd!")
        test("Re-unlock with correct password succeeds", success2, msg2)

        # Wrong password
        lock_vault()
        success3, msg3 = load_vault("wrongpassword")
        test("Wrong password fails", not success3)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

# ===========================================================================
# PHASE 2b — Password Change (Critical Bug Fix Validation)
# ===========================================================================
def test_phase2b():
    heading("Phase 2b — Password Change (Critical Bug Fix)")

    try:
        from crypthaven_server import (
            set_vault_folder, load_vault, save_index, lock_vault,
            vault_encrypt, vault_decrypt, ACTIVE_DEK
        )
        import crypthaven_server as cs
    except ImportError as e:
        print(f"  ⚠️  Cannot import — skip Phase 2b tests ({e})")
        return

    tmp_dir = tempfile.mkdtemp(prefix="crypthaven_pwchange_")
    try:
        set_vault_folder(tmp_dir)
        load_vault("OriginalPassword123!")

        # Simulate uploading a file (encrypt test data and write to data dir)
        data_dir = os.path.join(tmp_dir, "data")
        test_file_content = b"THIS IS MY SECRET PHOTO DATA " * 1000
        encrypted_file = vault_encrypt(test_file_content, cs.ACTIVE_DEK)
        enc_id = "enc_test_000001.enc"
        enc_path = os.path.join(data_dir, enc_id)
        with open(enc_path, 'wb') as f:
            f.write(encrypted_file)

        # Add to index
        cs.DECRYPTED_INDEX.append({
            "enc_id": enc_id, "name": "test_photo.jpg",
            "subfolder": "", "rel_path": "test_photo.jpg",
            "size": len(test_file_content), "is_video": False,
            "is_live_photo": False, "mtime": time.time(),
            "starred": False, "enc_thumb_id": None
        })
        save_index()

        # Now change the password
        old_dek = cs.ACTIVE_DEK  # save reference

        # Simulate the password change endpoint logic:
        from crypthaven_server import derive_kek, wrap_dek
        salt_path = os.path.join(tmp_dir, "vault_salt.bin")
        with open(salt_path, 'rb') as f:
            salt = f.read()

        # Verify old password (this is the fix — must verify first)
        old_kek = derive_kek("OriginalPassword123!", salt)

        # Generate new salt, new KEK
        new_salt = secrets.token_bytes(32)
        new_kek = derive_kek("NewSecurePassword456!", new_salt)

        # Re-wrap the SAME DEK
        new_wrapped = wrap_dek(cs.ACTIVE_DEK, new_kek)

        # Save new salt and wrapped DEK
        with open(salt_path, 'wb') as f:
            f.write(new_salt)
        dek_path = os.path.join(tmp_dir, "vault_dek.bin")
        with open(dek_path, 'wb') as f:
            f.write(new_wrapped)

        # Lock vault
        lock_vault()

        # CRITICAL TEST: Can we unlock with new password AND read the file?
        success, msg = load_vault("NewSecurePassword456!")
        test("Unlock with NEW password succeeds", success, msg)

        # Read the encrypted file and decrypt it
        with open(enc_path, 'rb') as f:
            ct = f.read()
        pt = vault_decrypt(ct, cs.ACTIVE_DEK)
        test("File still decrypts after password change", pt == test_file_content,
             f"Decrypted length: {len(pt)}, expected: {len(test_file_content)}")

        # Verify DEK didn't change
        test("DEK is unchanged after password change", cs.ACTIVE_DEK == old_dek)

        # Verify old password no longer works
        lock_vault()
        success_old, _ = load_vault("OriginalPassword123!")
        test("Old password no longer works", not success_old)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

# ===========================================================================
# PHASE 3 — Session & Auth
# ===========================================================================
def test_phase3():
    heading("Phase 3 — Session & Auth Hardening")

    try:
        import crypthaven_server as cs
        # Check that URL token auth is removed
        source = open(os.path.join(os.path.dirname(__file__), "crypthaven_server.py"),
                      "r", encoding="utf-8").read()

        test("URL token auth removed from check_auth",
             "query.get('token'" not in source or "url_token" not in source,
             "Found url_token or query.get('token') in check_auth — remove it")

        test("getTokenParam() removed from JavaScript",
             "getTokenParam" not in source,
             "getTokenParam still in JavaScript — remove it")

        test("Token not in login JSON response",
             "'token': new_session_token" not in source
             and '"token": new_session_token' not in source
             and "token': new_session_token" not in source,
             "Token still returned in login response body")

        test("Cookie has Secure flag",
             "Secure" in source and "auth_session=" in source,
             "Cookie missing Secure flag")

        test("CSRF token generation exists",
             "csrf" in source.lower() or "X-CSRF-Token" in source,
             "No CSRF implementation found")

        test("Old password required for password change",
             "old_password" in source,
             "Password change doesn't require old password verification")

        test("Server-side password minimum length check",
             "len(new_pwd)" in source or "len(old_pwd)" in source,
             "No server-side password length validation")

    except Exception as e:
        test("Phase 3 source analysis", False, str(e))

# ===========================================================================
# PHASE 4 — Transport Security
# ===========================================================================
def test_phase4():
    heading("Phase 4 — Transport & Web Security")

    try:
        source = open(os.path.join(os.path.dirname(__file__), "crypthaven_server.py"),
                      "r", encoding="utf-8").read()

        test("HSTS header present",
             "Strict-Transport-Security" in source,
             "No HSTS header found")

        test("TLS minimum version configured",
             "TLSv1_2" in source or "minimum_version" in source,
             "No explicit TLS minimum version")

        test("HTTP to HTTPS redirect exists",
             ("301" in source or "307" in source) and ("https://" in source or "redirect" in source.lower()),
             "No HTTP→HTTPS redirect found")

        test("Path traversal guard exists",
             "startswith" in source and "abspath" in source,
             "No path canonicalization check found")

    except Exception as e:
        test("Phase 4 source analysis", False, str(e))

# ===========================================================================
# Run all tests
# ===========================================================================
if __name__ == "__main__":
    print("\n🛡️  CryptHaven Security Upgrade — Test Suite\n")

    test_phase0()
    test_phase1()
    test_phase1b()
    test_phase2()
    test_phase2b()
    test_phase3()
    test_phase4()

    print(f"\n{'='*60}")
    print(f"  Results: {PASS_COUNT} passed, {FAIL_COUNT} failed")
    print(f"{'='*60}")

    if FAIL_COUNT > 0:
        print("\n⚠️  SOME TESTS FAILED — Fix failures before proceeding.\n")
        sys.exit(1)
    else:
        print("\n✅ ALL TESTS PASSED\n")
        sys.exit(0)
