# A part of NonVisual Desktop Access (NVDA)
# Copyright (C) 2025-2026 NV Access Limited and others.
# This file is covered by the GNU General Public License.
# See the file COPYING for more details.

"""End-to-end encryption for NVDA Remote.

Uses X25519 ephemeral key exchange with HKDF channel key binding for
per-session forward secrecy, and XSalsa20-Poly1305 authenticated encryption
(NaCl SecretBox) to protect data-plane messages from the relay server.

The channel key — already a shared secret between the two parties — is mixed
into the key derivation via HKDF so that a man-in-the-middle who does not know
the real channel key (e.g. the relay operator, who only sees a hash) derives a
different session key, causing all encrypted messages to fail decryption.

Requires PyNaCl (libsodium Python binding).
"""

import base64
import hashlib
import hmac
import json
import struct
from typing import Any

from logHandler import log
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random


_HKDF_INFO = b"nvda-remote-e2e"


class PeerKeyState:
	"""Tracks the E2E state for a single peer."""

	__slots__ = ("peer_id", "public_key", "nonce_prefix", "box", "send_counter")

	def __init__(self, peer_id: int, public_key: PublicKey, nonce_prefix: bytes):
		self.peer_id = peer_id
		self.public_key = public_key
		self.nonce_prefix = nonce_prefix
		self.box: SecretBox | None = None
		self.send_counter: int = 0


def hashChannelKey(channelKey: str) -> str:
	"""Hash a channel key for use as the JOIN routing label.

	The server never sees the real channel key — only this hash.
	"""
	return hashlib.sha256(channelKey.encode("utf-8")).hexdigest()


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
	"""HKDF-SHA256 extract-and-expand (RFC 5869), single block."""
	# Extract
	prk = hmac.new(salt, ikm, hashlib.sha256).digest()
	# Expand (single block — sufficient for length <= 32)
	okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
	return okm[:length]


class E2ESession:
	"""Manages E2E encryption for one channel session.

	Each session generates an ephemeral X25519 keypair. The shared secret
	from DH key exchange is fed through HKDF with the real channel key as
	salt, binding the session to the shared secret that the relay never sees.

	Lifecycle:
	1. Created when channel_joined arrives with e2e_available=True
	2. Broadcasts ephemeral public key via e2e_pubkey message
	3. Receives peer pubkeys, derives pairwise HKDF-bound shared secrets
	4. Encrypts all outbound data-plane messages
	5. Decrypts all inbound e2e_data messages
	6. Destroyed on disconnect
	"""

	def __init__(self, channelKey: str) -> None:
		self._channelKey = channelKey.encode("utf-8")
		self._private_key = PrivateKey.generate()
		self._public_key = self._private_key.public_key
		self._nonce_prefix = nacl_random(4)
		self._peers: dict[int, PeerKeyState] = {}
		log.debug("E2E: Generated ephemeral key pair")

	@property
	def public_key_b64(self) -> str:
		return base64.b64encode(bytes(self._public_key)).decode("ascii")

	@property
	def nonce_prefix_b64(self) -> str:
		return base64.b64encode(self._nonce_prefix).decode("ascii")

	def get_pubkey_message(self) -> dict[str, str]:
		"""Returns kwargs for transport.send(RemoteMessageType.E2E_PUBKEY, **kwargs)."""
		return {
			"pubkey": self.public_key_b64,
			"nonce_prefix": self.nonce_prefix_b64,
		}

	def add_peer(
		self,
		peer_id: int,
		pubkey_b64: str,
		nonce_prefix_b64: str,
	) -> None:
		"""Process a received e2e_pubkey message from a peer.

		Performs X25519 DH, derives the pairwise session key via HKDF
		with the channel key as salt, and stores the SecretBox.
		"""
		peer_pubkey = PublicKey(base64.b64decode(pubkey_b64))
		nonce_prefix = base64.b64decode(nonce_prefix_b64)
		peer = PeerKeyState(peer_id, peer_pubkey, nonce_prefix)
		# DH shared secret via NaCl crypto_box_beforenm (X25519 + HSalsa20)
		raw_shared = Box(self._private_key, peer_pubkey).shared_key()
		# Bind to channel key via HKDF
		derived_key = _hkdf_sha256(ikm=raw_shared, salt=self._channelKey, info=_HKDF_INFO)
		peer.box = SecretBox(derived_key)
		self._peers[peer_id] = peer
		log.info(f"E2E: Established pairwise key with peer {peer_id}")

	def remove_peer(self, peer_id: int) -> None:
		"""Remove a peer's key state (on disconnect)."""
		if peer_id in self._peers:
			log.info(f"E2E: Removed pairwise key for peer {peer_id}")
		self._peers.pop(peer_id, None)

	def has_peer(self, peer_id: int) -> bool:
		return peer_id in self._peers

	@property
	def peer_ids(self) -> list[int]:
		return list(self._peers.keys())

	def _make_nonce(self, peer: PeerKeyState) -> bytes:
		"""Build a 24-byte nonce for XSalsa20-Poly1305."""
		counter_bytes = struct.pack(">Q", peer.send_counter)
		peer.send_counter += 1
		return self._nonce_prefix + b"\x00" * 12 + counter_bytes

	def encrypt(self, type: str, from_id: int, **kwargs: Any) -> list[dict[str, Any]]:
		"""Encrypt a data-plane message for all peers.

		Returns a list of dicts, one per peer, each suitable as kwargs for:
			transport.send(RemoteMessageType.E2E_DATA, **msg)

		The sender's user_id is included inside the encrypted payload as '_from'
		for authenticity verification (defense-in-depth against a server that
		lies about the outer origin field).

		A '_to' field is intentionally omitted: pairwise SecretBox keys already
		ensure only the intended recipient can decrypt, and the '_from' check
		covers reflection attacks (server replaying your own message back to you).
		"""
		messages = []
		for peer in self._peers.values():
			if peer.box is None:
				log.error(f"E2E: Peer {peer.peer_id} has no derived box, skipping encryption")
				continue
			plaintext = json.dumps({"type": type, "_from": from_id, **kwargs}).encode("utf-8")
			nonce = self._make_nonce(peer)
			ciphertext = peer.box.encrypt(plaintext, nonce).ciphertext
			messages.append(
				{
					"to": peer.peer_id,
					"ciphertext": base64.b64encode(ciphertext).decode("ascii"),
					"nonce": base64.b64encode(nonce).decode("ascii"),
				},
			)
		return messages

	def encrypt_preserialized(
		self,
		type: str,
		from_id: int,
		serialized_kwargs: bytes,
	) -> list[dict[str, Any]]:
		"""Encrypt a pre-serialized data-plane message for all peers.

		This variant accepts kwargs already serialized as JSON bytes,
		which is needed for speech commands that require the custom
		SpeechCommandJSONEncoder. The caller is responsible for serializing
		the kwargs (without the 'type' and '_from' fields).

		:param type: The message type string.
		:param from_id: The sender's user_id.
		:param serialized_kwargs: The message kwargs serialized as JSON bytes
			(should be a JSON object without 'type' and '_from').
		"""
		messages = []
		for peer in self._peers.values():
			if peer.box is None:
				log.error(f"E2E: Peer {peer.peer_id} has no derived box, skipping encryption")
				continue
			obj = json.loads(serialized_kwargs)
			obj["type"] = type
			obj["_from"] = from_id
			plaintext = json.dumps(obj).encode("utf-8")
			nonce = self._make_nonce(peer)
			ciphertext = peer.box.encrypt(plaintext, nonce).ciphertext
			messages.append(
				{
					"to": peer.peer_id,
					"ciphertext": base64.b64encode(ciphertext).decode("ascii"),
					"nonce": base64.b64encode(nonce).decode("ascii"),
				},
			)
		return messages

	def decrypt(
		self,
		origin_id: int,
		ciphertext_b64: str,
		nonce_b64: str,
	) -> tuple[str, dict[str, Any]] | None:
		"""Decrypt an e2e_data message. Returns (message_type, kwargs) or None.

		Verifies that the '_from' field inside the decrypted payload matches
		the outer 'origin' set by the server. A mismatch indicates tampering.
		"""
		peer = self._peers.get(origin_id)
		if peer is None or peer.box is None:
			log.warning(f"E2E: No key for peer {origin_id}, cannot decrypt")
			return None
		try:
			ciphertext = base64.b64decode(ciphertext_b64)
			nonce = base64.b64decode(nonce_b64)
			plaintext = peer.box.decrypt(ciphertext, nonce)
			obj = json.loads(plaintext.decode("utf-8"))
			msg_type = obj.pop("type")
			# Verify sender authenticity: _from inside payload must match origin
			inner_from = obj.pop("_from", None)
			if inner_from is not None and inner_from != origin_id:
				log.warning(
					f"E2E: Origin mismatch — outer origin={origin_id}, inner _from={inner_from}. "
					"Possible tampering, rejecting message.",
				)
				return None
			log.debug(f"E2E: Decrypted message type '{msg_type}' from peer {origin_id}")
			return (msg_type, obj)
		except Exception:
			log.warning(
				f"E2E: Decryption failed for message from peer {origin_id}",
				exc_info=True,
			)
			return None
