"""Adversarial security and compatibility tests for CryptHaven.

All filesystem tests use temporary vaults. No repository or user vault data is read.
"""

import base64
import json
import http.client
import os
import secrets
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypthaven_server as cs


PASSWORD = "Correct Horse Battery Staple!"
NEW_PASSWORD = "A Different Strong Password!"


class TemporaryVaultTestCase(unittest.TestCase):
    def setUp(self):
        cs.lock_vault()
        self.temp_dir = tempfile.mkdtemp(prefix="crypthaven_security_test_")
        cs.set_vault_folder(self.temp_dir)

    def tearDown(self):
        cs.lock_vault()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def initialize(self, password=PASSWORD):
        success, message = cs.load_vault(password, allow_initialize=True)
        self.assertTrue(success, message)

    def create_legacy_vault(self):
        salt = secrets.token_bytes(16)
        fernet = Fernet(cs.derive_key(PASSWORD, salt))
        item = {
            "enc_id": "enc_legacy_media.enc",
            "name": "legacy.jpg",
            "subfolder": "",
            "rel_path": "legacy.jpg",
            "size": 18,
            "is_video": False,
            "is_live_photo": False,
            "mtime": time.time(),
            "starred": False,
            "enc_thumb_id": "enc_legacy_thumb.enc",
        }
        plaintext = b"legacy media bytes"
        thumbnail = b"legacy thumbnail"
        cs.atomic_write(cs.SALT_PATH, salt)
        cs.atomic_write(cs.INDEX_PATH, fernet.encrypt(json.dumps([item]).encode("utf-8")))
        cs.atomic_write(cs.safe_vault_path(item["enc_id"]), fernet.encrypt(plaintext))
        cs.atomic_write(cs.safe_vault_path(item["enc_thumb_id"]), fernet.encrypt(thumbnail))
        success, message = cs.load_vault(PASSWORD)
        self.assertTrue(success, message)
        return item, plaintext, thumbnail

    def create_v2_vault(self):
        salt = secrets.token_bytes(cs.KEK_SALT_SIZE)
        dek = cs.generate_dek()
        kek = cs.derive_kek(PASSWORD, salt)
        item = {
            "enc_id": "enc_v2_media.enc",
            "name": "v2.jpg",
            "subfolder": "",
            "rel_path": "v2.jpg",
            "size": 14,
            "is_video": False,
            "is_live_photo": False,
            "mtime": time.time(),
            "starred": False,
            "enc_thumb_id": "enc_v2_thumb.enc",
        }
        plaintext = b"v2 media bytes"
        thumbnail = b"v2 thumbnail"

        def encrypt_v2(value):
            nonce = secrets.token_bytes(cs.NONCE_SIZE)
            return b"\x02" + nonce + AESGCM(dek).encrypt(nonce, value, None)

        cs.atomic_write(cs.SALT_PATH, salt)
        cs.atomic_write(cs.DEK_PATH, cs.wrap_dek(dek, kek))
        cs.atomic_write(cs.INDEX_PATH, encrypt_v2(json.dumps([item]).encode("utf-8")))
        cs.atomic_write(cs.safe_vault_path(item["enc_id"]), encrypt_v2(plaintext))
        cs.atomic_write(cs.safe_vault_path(item["enc_thumb_id"]), encrypt_v2(thumbnail))
        success, message = cs.load_vault(PASSWORD)
        self.assertTrue(success, message)
        return item, plaintext, thumbnail, dek


class NetworkDiscoveryTests(unittest.TestCase):
    def test_lan_detection_excludes_warp_cgnat_and_keeps_wifi(self):
        address_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('100.96.0.1', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('10.0.0.47', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.168.50.12', 0)),
        ]
        route_socket = mock.MagicMock()
        route_socket.__enter__.return_value = route_socket
        route_socket.getsockname.return_value = ('100.96.0.1', 49152)
        with mock.patch.object(cs.socket, 'getaddrinfo', return_value=address_info), \
             mock.patch.object(cs.socket, 'gethostname', return_value='test-host'), \
             mock.patch.object(cs.socket, 'socket', return_value=route_socket):
            self.assertEqual(cs.detect_lan_ips(), ['10.0.0.47', '192.168.50.12'])

        self.assertFalse(cs.is_lan_ipv4('100.96.0.1'))
        self.assertFalse(cs.is_lan_ipv4('169.254.2.4'))
        self.assertTrue(cs.is_lan_ipv4('172.20.4.8'))

    def test_http_binding_targets_loopback_and_every_lan_address(self):
        created = []

        class DummyServer:
            def __init__(self, address, handler):
                created.append(address)

            def server_close(self):
                pass

        with mock.patch.object(cs, 'LAN_IPS', ['10.0.0.47', '192.168.50.12']), \
             mock.patch.object(cs, 'ThreadedHTTPServer', DummyServer):
            servers, port = cs.bind_http_server(18080)

        self.assertEqual(port, 18080)
        self.assertEqual(len(servers), 3)
        self.assertEqual(
            created,
            [('127.0.0.1', 18080), ('10.0.0.47', 18080), ('192.168.50.12', 18080)],
        )


class TLSAddressCoverageTests(TemporaryVaultTestCase):
    def test_generated_certificate_rotates_when_lan_addresses_change(self):
        with mock.patch.object(cs, 'LAN_IPS', ['192.168.1.20']), \
             mock.patch.object(cs, 'LOCAL_IP', '192.168.1.20'):
            self.assertTrue(cs.generate_self_signed_ssl_certificate())
            with open(cs.CERT_PATH, 'rb') as cert_file:
                original_certificate = cert_file.read()

        with mock.patch.object(cs, 'LAN_IPS', ['10.0.0.47']), \
             mock.patch.object(cs, 'LOCAL_IP', '10.0.0.47'):
            self.assertFalse(cs.tls_certificate_is_current())
            self.assertTrue(cs.generate_self_signed_ssl_certificate())
            self.assertTrue(cs.tls_certificate_is_current())
            with open(cs.CERT_PATH, 'rb') as cert_file:
                replacement_bytes = cert_file.read()
            replacement = cs.x509.load_pem_x509_certificate(replacement_bytes)
            san = replacement.extensions.get_extension_for_class(
                cs.x509.SubjectAlternativeName
            ).value
            covered = {str(value) for value in san.get_values_for_type(cs.x509.IPAddress)}

        self.assertNotEqual(original_certificate, replacement_bytes)
        self.assertEqual(covered, {'127.0.0.1', '10.0.0.47'})


class VaultHistoryTests(unittest.TestCase):
    def test_pyinstaller_temp_entries_are_removed_and_not_readded(self):
        with tempfile.TemporaryDirectory(prefix="crypthaven_history_test_") as appdata:
            real_vault = os.path.join(appdata, "Real Vault")
            os.makedirs(real_vault)
            stale_vault = os.path.join(appdata, "Local", "Temp", "_MEI123456", "vault")
            with mock.patch.dict(os.environ, {"APPDATA": appdata}, clear=False):
                config_path = cs.get_config_path()
                with open(config_path, "w", encoding="utf-8") as config_file:
                    json.dump({"recent_vaults": [stale_vault, real_vault, real_vault]}, config_file)

                self.assertEqual(cs.load_vault_history(), [os.path.abspath(real_vault)])
                cs.add_to_vault_history(stale_vault)
                self.assertEqual(cs.load_vault_history(), [os.path.abspath(real_vault)])
                with open(config_path, "r", encoding="utf-8") as config_file:
                    self.assertEqual(
                        json.load(config_file)["recent_vaults"],
                        [os.path.abspath(real_vault)],
                    )


class EncryptionCoreTests(unittest.TestCase):
    def test_v3_round_trip_tamper_and_context_binding(self):
        dek = cs.generate_dek()
        plaintext = secrets.token_bytes(4096)
        ciphertext = cs.vault_encrypt(plaintext, dek, context="media:item-a")

        self.assertEqual(ciphertext[0], 3)
        self.assertEqual(
            cs.vault_decrypt(ciphertext, dek, context="media:item-a"), plaintext
        )
        with self.assertRaises(InvalidTag):
            cs.vault_decrypt(ciphertext, dek, context="media:item-b")

        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        with self.assertRaises(InvalidTag):
            cs.vault_decrypt(bytes(tampered), dek, context="media:item-a")

    def test_v2_ciphertext_remains_readable(self):
        dek = cs.generate_dek()
        nonce = secrets.token_bytes(cs.NONCE_SIZE)
        plaintext = b"existing v2 payload"
        legacy_v2 = b"\x02" + nonce + AESGCM(dek).encrypt(nonce, plaintext, None)
        self.assertEqual(
            cs.vault_decrypt(legacy_v2, dek, context="ignored-for-v2"), plaintext
        )

    def test_key_wrap_authenticates_aad_and_length(self):
        dek = cs.generate_dek()
        kek = cs.generate_dek()
        wrapped = cs.wrap_dek(dek, kek, b"header-a")
        self.assertEqual(cs.unwrap_dek(wrapped, kek, b"header-a"), dek)
        with self.assertRaises(InvalidTag):
            cs.unwrap_dek(wrapped, kek, b"header-b")
        with self.assertRaises(ValueError):
            cs.unwrap_dek(wrapped[:-1], kek, b"header-a")


class VaultStateTests(TemporaryVaultTestCase):
    def test_initialization_requires_local_authorization_and_password_policy(self):
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "empty")
        success, _ = cs.load_vault(PASSWORD, allow_initialize=False)
        self.assertFalse(success)
        success, _ = cs.load_vault("short", allow_initialize=True)
        self.assertFalse(success)
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "empty")

        self.initialize()
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "v3")
        self.assertTrue(os.path.exists(cs.KEY_ENVELOPE_PATH))
        self.assertFalse(os.path.exists(cs.SALT_PATH))
        self.assertFalse(os.path.exists(cs.DEK_PATH))

    def test_partial_metadata_never_reinitializes_or_overwrites_data(self):
        orphan_path = cs.safe_vault_path("orphan.enc")
        orphan = secrets.token_bytes(128)
        cs.atomic_write(orphan_path, orphan)
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "damaged")

        success, message = cs.load_vault(PASSWORD, allow_initialize=True)
        self.assertFalse(success)
        self.assertIn("incomplete", message)
        with open(orphan_path, "rb") as orphan_file:
            self.assertEqual(orphan_file.read(), orphan)
        self.assertFalse(os.path.exists(cs.KEY_ENVELOPE_PATH))
        self.assertFalse(os.path.exists(cs.INDEX_PATH))

    def test_missing_index_fails_closed_without_replacing_key_envelope(self):
        self.initialize()
        with open(cs.KEY_ENVELOPE_PATH, "rb") as envelope_file:
            original_envelope = envelope_file.read()
        os.remove(cs.INDEX_PATH)
        cs.lock_vault()

        success, _ = cs.load_vault(NEW_PASSWORD, allow_initialize=True)
        self.assertFalse(success)
        with open(cs.KEY_ENVELOPE_PATH, "rb") as envelope_file:
            self.assertEqual(envelope_file.read(), original_envelope)


class PasswordChangeTests(TemporaryVaultTestCase):
    def test_password_change_is_atomic_and_preserves_media_dek(self):
        self.initialize()
        original_dek = cs.ACTIVE_DEK
        media_id = "enc_password_test.enc"
        plaintext = b"secret media survives password changes"
        cs.atomic_write(
            cs.safe_vault_path(media_id),
            cs.vault_encrypt(plaintext, original_dek, context=f"media:{media_id}"),
        )
        with open(cs.KEY_ENVELOPE_PATH, "rb") as envelope_file:
            original_envelope = envelope_file.read()

        with self.assertRaises(Exception):
            cs.change_vault_password("wrong password value", NEW_PASSWORD)
        with open(cs.KEY_ENVELOPE_PATH, "rb") as envelope_file:
            self.assertEqual(envelope_file.read(), original_envelope)

        cs.change_vault_password(PASSWORD, NEW_PASSWORD)
        self.assertEqual(cs.ACTIVE_DEK, original_dek)
        cs.lock_vault()
        self.assertFalse(cs.load_vault(PASSWORD)[0])
        self.assertTrue(cs.load_vault(NEW_PASSWORD)[0])
        with open(cs.safe_vault_path(media_id), "rb") as media_file:
            self.assertEqual(
                cs.vault_decrypt(
                    media_file.read(), cs.ACTIVE_DEK, context=f"media:{media_id}"
                ),
                plaintext,
            )


class MutationCommitTests(TemporaryVaultTestCase):
    def test_failed_index_commit_does_not_delete_ciphertext(self):
        self.initialize()
        item = {
            "enc_id": "enc_delete_test.enc",
            "name": "delete-test.jpg",
            "subfolder": "",
            "rel_path": "delete-test.jpg",
            "size": 4,
            "is_video": False,
            "is_live_photo": False,
            "mtime": time.time(),
            "starred": False,
            "enc_thumb_id": None,
        }
        media_path = cs.safe_vault_path(item["enc_id"])
        cs.atomic_write(
            media_path,
            cs.vault_encrypt(b"data", cs.ACTIVE_DEK, context=f"media:{item['enc_id']}")
        )
        cs.DECRYPTED_INDEX.append(item)
        cs.save_index()

        original_save_index = cs.save_index
        cs.save_index = lambda: (_ for _ in ()).throw(RuntimeError("injected failure"))
        try:
            with self.assertRaises(RuntimeError):
                cs.commit_item_deletions([item])
        finally:
            cs.save_index = original_save_index

        self.assertIn(item, cs.DECRYPTED_INDEX)
        self.assertTrue(os.path.exists(media_path))
        self.assertEqual(cs.commit_item_deletions([item]), 1)
        self.assertNotIn(item, cs.DECRYPTED_INDEX)
        self.assertFalse(os.path.exists(media_path))


class MigrationTests(TemporaryVaultTestCase):
    def test_legacy_migration_stages_verifies_and_commits(self):
        item, plaintext, thumbnail = self.create_legacy_vault()
        migrated = cs.migrate_legacy_vault(PASSWORD)
        self.assertEqual(migrated, 1)
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "v3")
        self.assertFalse(os.path.exists(cs.MIGRATION_JOURNAL_PATH))
        self.assertFalse(os.path.exists(cs.SALT_PATH))

        with open(cs.safe_vault_path(item["enc_id"]), "rb") as media_file:
            self.assertEqual(
                cs.vault_decrypt(
                    media_file.read(), cs.ACTIVE_DEK,
                    context=f"media:{item['enc_id']}"
                ),
                plaintext,
            )
        with open(cs.safe_vault_path(item["enc_thumb_id"]), "rb") as thumb_file:
            self.assertEqual(
                cs.vault_decrypt(
                    thumb_file.read(), cs.ACTIVE_DEK,
                    context=f"thumb:{item['enc_thumb_id']}"
                ),
                thumbnail,
            )

    def test_interruption_after_data_swap_rolls_back_legacy_vault(self):
        item, plaintext, _ = self.create_legacy_vault()
        with self.assertRaises(RuntimeError):
            cs.migrate_legacy_vault(PASSWORD, _fault_at="after_data_swap")

        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "legacy")
        self.assertFalse(os.path.exists(cs.MIGRATION_JOURNAL_PATH))
        cs.lock_vault()
        self.assertTrue(cs.load_vault(PASSWORD)[0])
        with open(cs.safe_vault_path(item["enc_id"]), "rb") as media_file:
            self.assertEqual(cs.ACTIVE_FERNET.decrypt(media_file.read()), plaintext)

    def test_interruption_after_index_replace_rolls_back_legacy_vault(self):
        self.create_legacy_vault()
        with self.assertRaises(RuntimeError):
            cs.migrate_legacy_vault(PASSWORD, _fault_at="after_index_replace")
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "legacy")
        cs.lock_vault()
        self.assertTrue(cs.load_vault(PASSWORD)[0])

    def test_v2_migration_reencrypts_every_payload_and_preserves_dek(self):
        item, plaintext, thumbnail, original_dek = self.create_v2_vault()
        self.assertEqual(cs.active_vault_format_version(), 2)

        migrated = cs.migrate_vault_to_v3(PASSWORD)

        self.assertEqual(migrated, 1)
        self.assertEqual(cs.active_vault_format_version(), 3)
        self.assertEqual(cs.ACTIVE_DEK, original_dek)
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "v3")
        self.assertFalse(os.path.exists(cs.SALT_PATH))
        self.assertFalse(os.path.exists(cs.DEK_PATH))
        for payload_path in (
            cs.INDEX_PATH,
            cs.safe_vault_path(item["enc_id"]),
            cs.safe_vault_path(item["enc_thumb_id"]),
        ):
            with open(payload_path, "rb") as payload_file:
                self.assertEqual(payload_file.read(1), b"\x03")

        with open(cs.safe_vault_path(item["enc_id"]), "rb") as media_file:
            self.assertEqual(
                cs.vault_decrypt(media_file.read(), cs.ACTIVE_DEK, context=f"media:{item['enc_id']}"),
                plaintext,
            )
        with open(cs.safe_vault_path(item["enc_thumb_id"]), "rb") as thumb_file:
            self.assertEqual(
                cs.vault_decrypt(thumb_file.read(), cs.ACTIVE_DEK, context=f"thumb:{item['enc_thumb_id']}"),
                thumbnail,
            )
        cs.lock_vault()
        self.assertTrue(cs.load_vault(PASSWORD)[0])

    def test_v2_migration_ignores_intentional_folder_placeholders(self):
        self.create_v2_vault()
        cs.DECRYPTED_INDEX.append({
            "enc_id": "enc_folder_placeholder.enc",
            "name": ".folder_placeholder",
            "subfolder": "Hand Curated",
            "rel_path": "Hand Curated/.folder_placeholder",
            "size": 0,
            "is_video": False,
            "is_live_photo": False,
            "mtime": time.time(),
            "starred": False,
            "enc_thumb_id": None,
        })
        cs.save_index()

        report = cs.scan_vault_integrity()
        self.assertEqual(report["placeholder_count"], 1)
        self.assertEqual(report["missing_media"], [])
        self.assertEqual(cs.migrate_vault_to_v3(PASSWORD), 1)
        self.assertEqual(cs.active_vault_format_version(), 3)

    def test_v2_interruption_rolls_back_all_live_paths(self):
        item, _, _, _ = self.create_v2_vault()
        original_paths = (
            cs.INDEX_PATH,
            cs.SALT_PATH,
            cs.DEK_PATH,
            cs.safe_vault_path(item["enc_id"]),
            cs.safe_vault_path(item["enc_thumb_id"]),
        )
        originals = {}
        for path in original_paths:
            with open(path, "rb") as source_file:
                originals[path] = source_file.read()

        with self.assertRaises(RuntimeError):
            cs.migrate_vault_to_v3(PASSWORD, _fault_at="after_index_replace")

        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "v2")
        self.assertFalse(os.path.exists(cs.KEY_ENVELOPE_PATH))
        self.assertFalse(os.path.exists(cs.MIGRATION_JOURNAL_PATH))
        for path, expected in originals.items():
            with open(path, "rb") as source_file:
                self.assertEqual(source_file.read(), expected)
        cs.lock_vault()
        self.assertTrue(cs.load_vault(PASSWORD)[0])

    def test_migration_refuses_unindexed_ciphertext_without_changing_vault(self):
        item, _, _, _ = self.create_v2_vault()
        orphan_path = cs.safe_vault_path("enc_orphan.enc")
        orphan = secrets.token_bytes(96)
        cs.atomic_write(orphan_path, orphan)
        with open(cs.INDEX_PATH, "rb") as index_file:
            original_index = index_file.read()

        with self.assertRaisesRegex(ValueError, "Unindexed ciphertext"):
            cs.migrate_vault_to_v3(PASSWORD)

        with open(cs.INDEX_PATH, "rb") as index_file:
            self.assertEqual(index_file.read(), original_index)
        with open(orphan_path, "rb") as orphan_file:
            self.assertEqual(orphan_file.read(), orphan)
        with open(cs.safe_vault_path(item["enc_id"]), "rb") as media_file:
            self.assertEqual(media_file.read(1), b"\x02")
        self.assertEqual(cs.vault_metadata_state(self.temp_dir), "v2")

    def test_mixed_v2_v3_payloads_remain_migration_eligible(self):
        item, _, _, _ = self.create_v2_vault()
        cs.save_index()
        with open(cs.INDEX_PATH, "rb") as index_file:
            self.assertEqual(index_file.read(1), b"\x03")
        with open(cs.safe_vault_path(item["enc_id"]), "rb") as media_file:
            self.assertEqual(media_file.read(1), b"\x02")
        self.assertEqual(cs.active_vault_format_version(), 2)
        self.assertEqual(cs.migrate_vault_to_v3(PASSWORD), 1)
        self.assertEqual(cs.active_vault_format_version(), 3)

    def test_v2_with_new_key_envelope_still_migrates_remaining_payloads(self):
        item, _, _, original_dek = self.create_v2_vault()
        cs.change_vault_password(PASSWORD, NEW_PASSWORD)
        self.assertTrue(os.path.exists(cs.KEY_ENVELOPE_PATH))
        self.assertFalse(os.path.exists(cs.SALT_PATH))
        self.assertFalse(os.path.exists(cs.DEK_PATH))
        with open(cs.safe_vault_path(item["enc_id"]), "rb") as media_file:
            self.assertEqual(media_file.read(1), b"\x02")
        self.assertEqual(cs.active_vault_format_version(), 2)

        self.assertEqual(cs.migrate_vault_to_v3(NEW_PASSWORD), 1)
        self.assertEqual(cs.ACTIVE_DEK, original_dek)
        self.assertEqual(cs.active_vault_format_version(), 3)
        cs.lock_vault()
        self.assertTrue(cs.load_vault(NEW_PASSWORD)[0])


class IntegrityRepairTests(TemporaryVaultTestCase):
    def add_item(self, enc_id, name, *, thumb_id=None, media=None, thumbnail=None):
        item = {
            "enc_id": enc_id,
            "name": name,
            "subfolder": "",
            "rel_path": name,
            "size": len(media or b""),
            "is_video": False,
            "is_live_photo": False,
            "mtime": time.time(),
            "starred": False,
            "enc_thumb_id": thumb_id,
        }
        cs.DECRYPTED_INDEX.append(item)
        if media is not None:
            cs.atomic_write(
                cs.safe_vault_path(enc_id),
                cs.vault_encrypt(media, cs.ACTIVE_DEK, context=f"media:{enc_id}"),
            )
        if thumb_id and thumbnail is not None:
            cs.atomic_write(
                cs.safe_vault_path(thumb_id),
                cs.vault_encrypt(thumbnail, cs.ACTIVE_DEK, context=f"thumb:{thumb_id}"),
            )
        return item

    def test_scan_classifies_discrepancies_without_touching_placeholders(self):
        self.initialize()
        self.add_item("enc_present.enc", "present.jpg", media=b"present")
        self.add_item("enc_missing.enc", "missing.jpg")
        self.add_item(
            "enc_thumb_media.enc", "missing-thumb.jpg",
            thumb_id="enc_missing_thumb.enc", media=b"thumbnail source",
        )
        cs.DECRYPTED_INDEX.append({
            "enc_id": "enc_folder_no_payload.enc",
            "name": ".folder_placeholder",
            "subfolder": "Archive",
            "rel_path": "Archive/.folder_placeholder",
            "size": 0,
        })
        cs.atomic_write(cs.safe_vault_path("enc_orphan.enc"), b"opaque orphan")
        cs.save_index()

        report = cs.scan_vault_integrity()
        self.assertEqual([x["enc_id"] for x in report["missing_media"]], ["enc_missing.enc"])
        self.assertEqual(
            [x["enc_thumb_id"] for x in report["missing_thumbnails"]],
            ["enc_missing_thumb.enc"],
        )
        self.assertEqual(
            [x["enc_id"] for x in report["unindexed_ciphertext"]],
            ["enc_orphan.enc"],
        )
        self.assertEqual(report["placeholder_count"], 1)
        self.assertTrue(report["migration_blocked"])

    def test_missing_thumbnail_repair_is_backed_up_and_regenerable(self):
        self.initialize()
        item = self.add_item(
            "enc_media.enc", "photo.jpg", thumb_id="enc_gone_thumb.enc", media=b"photo",
        )
        cs.save_index()

        result = cs.repair_vault_integrity(
            "clear_missing_thumbnails", ["enc_gone_thumb.enc"]
        )

        self.assertEqual(result["affected_count"], 1)
        self.assertIsNone(item["enc_thumb_id"])
        self.assertTrue(os.path.isfile(os.path.join(result["recovery_path"], "original-vault_index.json")))
        with open(os.path.join(result["recovery_path"], "manifest.json"), encoding="utf-8") as manifest_file:
            self.assertEqual(json.load(manifest_file)["status"], "completed")
        self.assertTrue(result["report"]["healthy"])

    def test_missing_media_removal_preserves_companion_thumbnail_in_recovery(self):
        self.initialize()
        item = self.add_item(
            "enc_missing_media.enc", "lost.jpg",
            thumb_id="enc_surviving_thumb.enc", thumbnail=b"surviving thumbnail",
        )
        cs.save_index()

        result = cs.repair_vault_integrity("remove_missing_media", [item["enc_id"]])

        self.assertNotIn(item, cs.DECRYPTED_INDEX)
        self.assertFalse(os.path.exists(cs.safe_vault_path("enc_surviving_thumb.enc")))
        preserved = os.path.join(
            result["recovery_path"], "ciphertext", "enc_surviving_thumb.enc"
        )
        self.assertTrue(os.path.isfile(preserved))
        self.assertTrue(result["report"]["healthy"])

    def test_unindexed_ciphertext_is_quarantined_not_deleted(self):
        self.initialize()
        orphan_id = "enc_unindexed.enc"
        original = b"unindexed ciphertext bytes"
        cs.atomic_write(cs.safe_vault_path(orphan_id), original)

        result = cs.repair_vault_integrity("quarantine_unindexed", [orphan_id])

        self.assertFalse(os.path.exists(cs.safe_vault_path(orphan_id)))
        quarantined = os.path.join(result["recovery_path"], "ciphertext", orphan_id)
        with open(quarantined, "rb") as quarantine_file:
            self.assertEqual(quarantine_file.read(), original)
        self.assertTrue(result["report"]["healthy"])


class InputAndSessionTests(TemporaryVaultTestCase):
    def test_paths_names_and_encrypted_ids_reject_escape_or_markup(self):
        export_root = os.path.join(self.temp_dir, "export")
        os.makedirs(export_root)
        with self.assertRaises(ValueError):
            cs.safe_child_path(export_root, "..", "outside.txt")
        with self.assertRaises(ValueError):
            cs.validate_filename("..\\outside.txt")
        with self.assertRaises(ValueError):
            cs.normalize_subfolder("safe/../../outside")
        with self.assertRaises(ValueError):
            cs.validate_encrypted_id("x' onerror='alert(1)")

    def test_request_size_limit_rejects_oversized_upload_before_read(self):
        handler = object.__new__(cs.VaultGalleryHandler)
        handler.headers = {
            "Content-Length": str(cs.MAX_UPLOAD_BYTES + cs.MAX_REQUEST_METADATA_BYTES + 1)
        }
        responses = []
        handler.send_json = lambda data, status=200: responses.append((status, data))
        self.assertFalse(handler.validate_request_size('/api/upload'))
        self.assertEqual(responses[0][0], 413)

    def test_expired_session_is_rejected_and_csrf_covers_header_auth(self):
        self.initialize()
        token = "a" * 32
        csrf = "b" * 64
        cs.ACTIVE_SESSIONS[token] = {
            "csrf": csrf,
            "created": time.time() - cs.SESSION_ABSOLUTE_TIMEOUT_SECONDS - 1,
            "last_seen": time.time(),
        }
        handler = object.__new__(cs.VaultGalleryHandler)
        handler.headers = {"X-Auth-Token": token, "X-CSRF-Token": csrf}
        handler.client_address = ("127.0.0.1", 12345)
        self.assertFalse(handler.check_auth())
        self.assertNotIn(token, cs.ACTIVE_SESSIONS)

        fresh_token = "c" * 32
        cs.ACTIVE_SESSIONS[fresh_token] = {
            "csrf": csrf, "created": time.time(), "last_seen": time.time()
        }
        handler.headers = {"X-Auth-Token": fresh_token}
        self.assertTrue(handler.check_auth())
        self.assertFalse(handler.validate_csrf())
        handler.headers["X-CSRF-Token"] = csrf
        self.assertTrue(handler.validate_csrf())


class HTTPIntegrationTests(TemporaryVaultTestCase):
    def setUp(self):
        super().setUp()
        self.assertTrue(cs.generate_self_signed_ssl_certificate())
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(cs.CERT_PATH, cs.KEY_PATH)
        self.server = cs.ThreadedHTTPServer(('127.0.0.1', 0), cs.VaultGalleryHandler)
        self.server.socket = tls_context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client_context = ssl.create_default_context()
        self.client_context.check_hostname = False
        self.client_context.verify_mode = ssl.CERT_NONE

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        super().tearDown()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPSConnection(
            '127.0.0.1', self.port, context=self.client_context, timeout=10
        )
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        result = response.status, response.getheaders(), payload
        connection.close()
        return result

    def test_login_csrf_authenticated_api_logout_and_size_limit(self):
        login_body = urllib.parse.urlencode({'password': PASSWORD})
        status, headers, _ = self.request(
            'POST', '/login', login_body,
            {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        )
        self.assertEqual(status, 200)
        cookie_values = [value for name, value in headers if name.lower() == 'set-cookie']
        auth_cookie = next(value.split(';', 1)[0] for value in cookie_values if value.startswith('auth_session='))
        csrf_cookie = next(value.split(';', 1)[0] for value in cookie_values if value.startswith('csrf_token='))
        csrf_token = csrf_cookie.split('=', 1)[1]
        cookie_header = f'{auth_cookie}; {csrf_cookie}'

        status, _, _ = self.request('GET', '/api/folders', headers={'Cookie': cookie_header})
        self.assertEqual(status, 200)

        status, _, payload = self.request(
            'GET', '/api/admin/integrity', headers={'Cookie': cookie_header}
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["healthy"])

        orphan_id = "enc_http_orphan.enc"
        cs.atomic_write(cs.safe_vault_path(orphan_id), b"synthetic orphan")
        repair_body = json.dumps({
            "action": "quarantine_unindexed", "enc_ids": [orphan_id]
        })
        status, _, payload = self.request(
            'POST', '/api/admin/integrity/repair', repair_body,
            {
                'Cookie': cookie_header,
                'X-CSRF-Token': csrf_token,
                'Content-Type': 'application/json',
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["affected_count"], 1)
        self.assertFalse(os.path.exists(cs.safe_vault_path(orphan_id)))

        status, _, _ = self.request(
            'POST', '/api/admin/cloud_backup', headers={'Cookie': cookie_header}
        )
        self.assertEqual(status, 403)

        status, _, _ = self.request(
            'POST', '/logout',
            headers={'Cookie': cookie_header, 'X-CSRF-Token': csrf_token}
        )
        self.assertEqual(status, 200)
        status, _, _ = self.request('GET', '/api/folders', headers={'Cookie': cookie_header})
        self.assertEqual(status, 401)

        status, _, _ = self.request(
            'POST', '/login', b'',
            {'Content-Length': str(cs.MAX_LOGIN_BODY_BYTES + 1), 'Accept': 'application/json'}
        )
        self.assertEqual(status, 413)

    def test_http_redirect_does_not_reflect_untrusted_host(self):
        redirect_server = cs.ThreadedHTTPServer(('127.0.0.1', 0), cs.HTTPRedirectHandler)
        redirect_port = redirect_server.server_address[1]
        redirect_thread = threading.Thread(target=redirect_server.serve_forever, daemon=True)
        redirect_thread.start()
        try:
            connection = http.client.HTTPConnection('127.0.0.1', redirect_port, timeout=10)
            connection.request('GET', '/login', headers={'Host': 'attacker.example'})
            response = connection.getresponse()
            self.assertEqual(response.status, 307)
            self.assertNotIn('attacker.example', response.getheader('Location'))
            response.read()
            connection.close()
        finally:
            redirect_server.shutdown()
            redirect_server.server_close()
            redirect_thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
