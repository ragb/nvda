# A part of NonVisual Desktop Access (NVDA)
# Copyright (C) 2025-2026 NV Access Limited
# This file is covered by the GNU General Public License.
# See the file COPYING for more details.

import json
import tempfile
import unittest
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from _remoteClient.e2e import E2ESession, loadOrGenerateIdentityKey


def _makeSession() -> E2ESession:
	"""Create an E2ESession with a fresh identity key."""
	return E2ESession(SigningKey.generate())


def _exchangeKeys(alice: E2ESession, bob: E2ESession, aliceId: int = 1, bobId: int = 2) -> None:
	"""Perform a full signed key exchange between two sessions."""
	aliceMsg = alice.get_pubkey_message()
	bobMsg = bob.get_pubkey_message()
	alice.add_peer(bobId, bobMsg["pubkey"], bobMsg["nonce_prefix"], bobMsg["identity_key"], bobMsg["signature"])
	bob.add_peer(aliceId, aliceMsg["pubkey"], aliceMsg["nonce_prefix"], aliceMsg["identity_key"], aliceMsg["signature"])


class TestE2EKeyExchange(unittest.TestCase):
	"""Test E2E key exchange and pairwise key establishment."""

	def test_pubkeyMessageFormat(self):
		session = _makeSession()
		msg = session.get_pubkey_message()
		self.assertIn("pubkey", msg)
		self.assertIn("nonce_prefix", msg)
		self.assertIn("identity_key", msg)
		self.assertIn("signature", msg)
		for key in msg:
			self.assertIsInstance(msg[key], str)

	def test_addPeerEstablishesKey(self):
		alice = _makeSession()
		bob = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"], aliceMsg["identity_key"], aliceMsg["signature"])
		self.assertTrue(bob.has_peer(1))
		self.assertIn(1, bob.peer_ids)

	def test_addPeerReturnsIdentityKey(self):
		alice = _makeSession()
		bob = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		identity = bob.add_peer(
			1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"], aliceMsg["identity_key"], aliceMsg["signature"],
		)
		self.assertEqual(identity, alice._identityKey.verify_key)

	def test_invalidSignatureRejected(self):
		alice = _makeSession()
		bob = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		# Tamper with the signature
		import base64

		bad_sig = base64.b64encode(b"\x00" * 64).decode("ascii")
		with self.assertRaises(BadSignatureError):
			bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"], aliceMsg["identity_key"], bad_sig)

	def test_wrongIdentityKeyRejected(self):
		"""Signature from a different identity key should fail verification."""
		alice = _makeSession()
		bob = _makeSession()
		eve = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		# Use Eve's identity key with Alice's signature — should fail
		with self.assertRaises(BadSignatureError):
			bob.add_peer(
				1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"],
				eve.identity_key_b64, aliceMsg["signature"],
			)

	def test_removePeer(self):
		alice = _makeSession()
		bob = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"], aliceMsg["identity_key"], aliceMsg["signature"])
		bob.remove_peer(1)
		self.assertFalse(bob.has_peer(1))

	def test_removeNonexistentPeerNoError(self):
		session = _makeSession()
		session.remove_peer(999)


class TestE2EEncryptDecrypt(unittest.TestCase):
	"""Test encryption and decryption of messages."""

	def setUp(self):
		self.alice = _makeSession()
		self.bob = _makeSession()
		_exchangeKeys(self.alice, self.bob)

	def test_encryptProducesOneMessagePerPeer(self):
		messages = self.alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		self.assertEqual(len(messages), 1)
		self.assertIn("ciphertext", messages[0])
		self.assertIn("nonce", messages[0])
		self.assertIn("to", messages[0])
		self.assertEqual(messages[0]["to"], 2)

	def test_roundTrip(self):
		messages = self.alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		result = self.bob.decrypt(1, messages[0]["ciphertext"], messages[0]["nonce"])
		self.assertIsNotNone(result)
		msg_type, kwargs = result
		self.assertEqual(msg_type, "key")
		self.assertEqual(kwargs["vk_code"], 65)
		self.assertTrue(kwargs["pressed"])

	def test_roundTripPreserialized(self):
		kwargs = {"sequence": ["hello"], "priority": "normal"}
		serialized = json.dumps(kwargs).encode("utf-8")
		messages = self.alice.encrypt_preserialized("speak", from_id=1, serialized_kwargs=serialized)
		result = self.bob.decrypt(1, messages[0]["ciphertext"], messages[0]["nonce"])
		self.assertIsNotNone(result)
		msg_type, decoded_kwargs = result
		self.assertEqual(msg_type, "speak")
		self.assertEqual(decoded_kwargs["sequence"], ["hello"])

	def test_bidirectional(self):
		"""Both sides can encrypt and the other can decrypt."""
		msgs_a = self.alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		msgs_b = self.bob.encrypt("tone", from_id=2, hz=440, length=100)
		result_a = self.bob.decrypt(1, msgs_a[0]["ciphertext"], msgs_a[0]["nonce"])
		result_b = self.alice.decrypt(2, msgs_b[0]["ciphertext"], msgs_b[0]["nonce"])
		self.assertEqual(result_a[0], "key")
		self.assertEqual(result_b[0], "tone")

	def test_decryptFromUnknownPeerReturnsNone(self):
		messages = self.alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		result = self.bob.decrypt(999, messages[0]["ciphertext"], messages[0]["nonce"])
		self.assertIsNone(result)

	def test_tamperedCiphertextReturnsNone(self):
		messages = self.alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		result = self.bob.decrypt(1, "dGFtcGVyZWQ=", messages[0]["nonce"])
		self.assertIsNone(result)

	def test_originMismatchReturnsNone(self):
		"""Inner _from must match the outer origin_id."""
		messages = self.alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		result = self.bob.decrypt(999, messages[0]["ciphertext"], messages[0]["nonce"])
		self.assertIsNone(result)


class TestE2EFingerprint(unittest.TestCase):
	"""Test fingerprint generation based on persistent identity keys."""

	def test_fingerprintMatchesBothSides(self):
		alice = _makeSession()
		bob = _makeSession()
		_exchangeKeys(alice, bob)
		self.assertEqual(alice.get_fingerprint(2), bob.get_fingerprint(1))

	def test_fingerprintStableAcrossSessions(self):
		"""Same identity keys should produce the same fingerprint in different sessions."""
		identityA = SigningKey.generate()
		identityB = SigningKey.generate()
		# Session 1
		alice1 = E2ESession(identityA)
		bob1 = E2ESession(identityB)
		_exchangeKeys(alice1, bob1)
		fp1 = alice1.get_fingerprint(2)
		# Session 2 (new ephemeral keys, same identity)
		alice2 = E2ESession(identityA)
		bob2 = E2ESession(identityB)
		_exchangeKeys(alice2, bob2)
		fp2 = alice2.get_fingerprint(2)
		self.assertEqual(fp1, fp2)

	def test_fingerprintForUnknownPeerReturnsNone(self):
		session = _makeSession()
		self.assertIsNone(session.get_fingerprint(999))

	def test_fingerprintFormat(self):
		alice = _makeSession()
		bob = _makeSession()
		_exchangeKeys(alice, bob)
		fingerprint = alice.get_fingerprint(2)
		self.assertIsNotNone(fingerprint)
		# Should be 4 groups of 4 hex chars separated by spaces
		parts = fingerprint.split(" ")
		self.assertEqual(len(parts), 4)
		for part in parts:
			self.assertEqual(len(part), 4)
			int(part, 16)  # Should not raise


class TestE2EMultiplePeers(unittest.TestCase):
	"""Test E2E with more than two peers in a channel."""

	def test_encryptForMultiplePeers(self):
		alice = _makeSession()
		bob = _makeSession()
		carol = _makeSession()
		bobMsg = bob.get_pubkey_message()
		carolMsg = carol.get_pubkey_message()
		alice.add_peer(2, bobMsg["pubkey"], bobMsg["nonce_prefix"], bobMsg["identity_key"], bobMsg["signature"])
		alice.add_peer(3, carolMsg["pubkey"], carolMsg["nonce_prefix"], carolMsg["identity_key"], carolMsg["signature"])
		messages = alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		self.assertEqual(len(messages), 2)
		recipients = {m["to"] for m in messages}
		self.assertEqual(recipients, {2, 3})

	def test_removePeerReducesRecipients(self):
		alice = _makeSession()
		bob = _makeSession()
		carol = _makeSession()
		bobMsg = bob.get_pubkey_message()
		carolMsg = carol.get_pubkey_message()
		alice.add_peer(2, bobMsg["pubkey"], bobMsg["nonce_prefix"], bobMsg["identity_key"], bobMsg["signature"])
		alice.add_peer(3, carolMsg["pubkey"], carolMsg["nonce_prefix"], carolMsg["identity_key"], carolMsg["signature"])
		alice.remove_peer(3)
		messages = alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		self.assertEqual(len(messages), 1)
		self.assertEqual(messages[0]["to"], 2)


class TestIdentityKeyPersistence(unittest.TestCase):
	"""Test persistent identity key loading and generation."""

	def test_generateAndReload(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			keyDir = Path(tmpdir)
			key1 = loadOrGenerateIdentityKey(keyDir)
			key2 = loadOrGenerateIdentityKey(keyDir)
			self.assertEqual(bytes(key1.verify_key), bytes(key2.verify_key))

	def test_generateCreatesFile(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			keyDir = Path(tmpdir)
			loadOrGenerateIdentityKey(keyDir)
			self.assertTrue((keyDir / "identity.key").exists())
			self.assertEqual(len((keyDir / "identity.key").read_bytes()), 32)

	def test_corruptedKeyRegenerates(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			keyDir = Path(tmpdir)
			key1 = loadOrGenerateIdentityKey(keyDir)
			# Corrupt the key file
			(keyDir / "identity.key").write_bytes(b"bad")
			key2 = loadOrGenerateIdentityKey(keyDir)
			# Should have generated a new key
			self.assertNotEqual(bytes(key1.verify_key), bytes(key2.verify_key))


if __name__ == "__main__":
	unittest.main()
