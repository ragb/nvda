# A part of NonVisual Desktop Access (NVDA)
# Copyright (C) 2025-2026 NV Access Limited
# This file is covered by the GNU General Public License.
# See the file COPYING for more details.

import json
import unittest

from _remoteClient.e2e import E2ESession, hashChannelKey, _hkdf_sha256


def _makeSession(channelKey: str = "test-channel-key") -> E2ESession:
	"""Create an E2ESession with a fresh ephemeral key."""
	return E2ESession(channelKey)


def _exchangeKeys(alice: E2ESession, bob: E2ESession, aliceId: int = 1, bobId: int = 2) -> None:
	"""Perform a full key exchange between two sessions."""
	aliceMsg = alice.get_pubkey_message()
	bobMsg = bob.get_pubkey_message()
	alice.add_peer(bobId, bobMsg["pubkey"], bobMsg["nonce_prefix"])
	bob.add_peer(aliceId, aliceMsg["pubkey"], aliceMsg["nonce_prefix"])


class TestChannelKeyHashing(unittest.TestCase):
	"""Test channel key hashing for JOIN messages."""

	def test_hashIsDeterministic(self):
		self.assertEqual(hashChannelKey("my-key"), hashChannelKey("my-key"))

	def test_hashDiffersForDifferentKeys(self):
		self.assertNotEqual(hashChannelKey("key-a"), hashChannelKey("key-b"))

	def test_hashIsSha256Hex(self):
		h = hashChannelKey("test")
		self.assertEqual(len(h), 64)
		int(h, 16)  # Should not raise


class TestHKDF(unittest.TestCase):
	"""Test HKDF-SHA256 key derivation."""

	def test_deterministicOutput(self):
		key1 = _hkdf_sha256(b"ikm", b"salt", b"info")
		key2 = _hkdf_sha256(b"ikm", b"salt", b"info")
		self.assertEqual(key1, key2)

	def test_differentSaltProducesDifferentKey(self):
		key1 = _hkdf_sha256(b"ikm", b"salt-a", b"info")
		key2 = _hkdf_sha256(b"ikm", b"salt-b", b"info")
		self.assertNotEqual(key1, key2)

	def test_outputLength(self):
		key = _hkdf_sha256(b"ikm", b"salt", b"info", length=32)
		self.assertEqual(len(key), 32)


class TestE2EKeyExchange(unittest.TestCase):
	"""Test E2E key exchange and pairwise key establishment."""

	def test_pubkeyMessageFormat(self):
		session = _makeSession()
		msg = session.get_pubkey_message()
		self.assertIn("pubkey", msg)
		self.assertIn("nonce_prefix", msg)
		self.assertEqual(len(msg), 2)
		for key in msg:
			self.assertIsInstance(msg[key], str)

	def test_addPeerEstablishesKey(self):
		alice = _makeSession()
		bob = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"])
		self.assertTrue(bob.has_peer(1))
		self.assertIn(1, bob.peer_ids)

	def test_removePeer(self):
		alice = _makeSession()
		bob = _makeSession()
		aliceMsg = alice.get_pubkey_message()
		bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"])
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


class TestE2EChannelKeyBinding(unittest.TestCase):
	"""Test that different channel keys produce incompatible sessions."""

	def test_mismatchedChannelKeyCannotDecrypt(self):
		"""Two sessions with different channel keys cannot communicate."""
		alice = E2ESession("channel-key-A")
		bob = E2ESession("channel-key-B")
		aliceMsg = alice.get_pubkey_message()
		bobMsg = bob.get_pubkey_message()
		alice.add_peer(2, bobMsg["pubkey"], bobMsg["nonce_prefix"])
		bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"])
		# Alice encrypts with key derived from "channel-key-A"
		messages = alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		# Bob tries to decrypt with key derived from "channel-key-B" — should fail
		result = bob.decrypt(1, messages[0]["ciphertext"], messages[0]["nonce"])
		self.assertIsNone(result)

	def test_sameChannelKeyCanDecrypt(self):
		"""Two sessions with the same channel key can communicate."""
		alice = E2ESession("same-key")
		bob = E2ESession("same-key")
		aliceMsg = alice.get_pubkey_message()
		bobMsg = bob.get_pubkey_message()
		alice.add_peer(2, bobMsg["pubkey"], bobMsg["nonce_prefix"])
		bob.add_peer(1, aliceMsg["pubkey"], aliceMsg["nonce_prefix"])
		messages = alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		result = bob.decrypt(1, messages[0]["ciphertext"], messages[0]["nonce"])
		self.assertIsNotNone(result)
		self.assertEqual(result[0], "key")


class TestE2EMultiplePeers(unittest.TestCase):
	"""Test E2E with more than two peers in a channel."""

	def test_encryptForMultiplePeers(self):
		alice = _makeSession()
		bob = _makeSession()
		carol = _makeSession()
		bobMsg = bob.get_pubkey_message()
		carolMsg = carol.get_pubkey_message()
		alice.add_peer(2, bobMsg["pubkey"], bobMsg["nonce_prefix"])
		alice.add_peer(3, carolMsg["pubkey"], carolMsg["nonce_prefix"])
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
		alice.add_peer(2, bobMsg["pubkey"], bobMsg["nonce_prefix"])
		alice.add_peer(3, carolMsg["pubkey"], carolMsg["nonce_prefix"])
		alice.remove_peer(3)
		messages = alice.encrypt("key", from_id=1, vk_code=65, pressed=True)
		self.assertEqual(len(messages), 1)
		self.assertEqual(messages[0]["to"], 2)


if __name__ == "__main__":
	unittest.main()
