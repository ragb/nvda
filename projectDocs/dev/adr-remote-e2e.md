### ADR status

* [x] Proposed
* [ ] Accepted
* [ ] Rejected
* [ ] Superseded

### Impact area

* Security / privacy
* Core architecture
* Add-on API / infrastructure
* Remote Access

### Related issues, PRs, discussions, or mailing list threads

* #17784 — Original feature request for E2E encryption in Remote Access
* #19857 — Closed prototype PR with full implementation (available as reference)
* [nvaccess/remote-server](https://github.com/nvaccess/remote-server) — Official Python relay server (needs v3 changes described in this ADR)
* [nvda-remote-server-rs](https://github.com/ragb/nvda-remote-server-rs) — Rust relay server with full protocol v3 support (used for development and testing)

### Context and problem statement

NVDA Remote Access allows two NVDA instances to communicate either through a relay server or by connecting directly to another host.
All connections (both direct and relay) are already encrypted using TLS, so data is protected from network eavesdroppers.
However, when using a relay server, the server terminates TLS on both sides: it decrypts traffic from client A, reads the plaintext, and re-encrypts it before forwarding to client B.
This means that anyone with access to the relay server — whether the operator or an attacker who compromises it — can see all session content: keystrokes, speech output, braille display data, and clipboard text.

Users who connect through public or third-party relay servers must fully trust both the operator and the security of the server infrastructure.
There is currently no way to verify that a relay server is not logging or inspecting session content.
E2E encryption also reduces liability for relay operators — they cannot leak data they never had access to in the first place.

**Direct connections are not affected.**
When one NVDA instance connects directly to another (via "Host control server"), the TLS tunnel runs point-to-point between the two machines with no intermediary.
The only parties that can read the traffic are the two endpoints, which already have full access to their own screen readers.
Adding E2E on top of a direct TLS connection would add complexity for zero security benefit.

This ADR proposes adding end-to-end encryption (E2E) to relay connections so that the relay server can only see encrypted ciphertext, not session content.

### UX impact via user stories

* As a screen reader user connecting through a relay server, I want my keystrokes and speech to be encrypted so that no one with access to the server — whether the operator or an attacker — can read them.
* As a user connecting to a relay server that does not support E2E (older server software), I want to be warned that my session is not end-to-end encrypted, so I can decide whether to continue or disconnect.
* As a user who needs to connect to a computer running an older NVDA version that does not support E2E, I want a setting to disable E2E so I can still connect.
* As a user connecting directly (not through a relay), I expect no change in behavior — direct connections are already private via TLS.
* As an add-on developer defining custom Remote Access message types, I want my messages to be automatically encrypted when E2E is active, without needing to opt in.

### Decision drivers

* **Strong MITM protection**: The relay operator should not be able to perform a man-in-the-middle attack on the key exchange, even on the very first connection. The channel key — already a shared secret between the two parties — is the natural authentication material for this.
* **Simplicity**: The fewer moving parts, the fewer places for bugs. No persistent keys, no trust stores, no identity management, no user-facing security decisions beyond "use E2E or not."
* **Minimal relay server changes**: The relay server should require only small, additive changes — no cryptographic code, no new dependencies. The server's role is to relay opaquely.
* **Proven cryptographic primitives**: Use well-understood algorithms (X25519, XSalsa20-Poly1305, HKDF) from a mature library (PyNaCl/libsodium) rather than designing custom crypto.
* **Single dependency**: PyNaCl wraps libsodium and provides key exchange, authenticated encryption, and hashing in one package.
* **Extensibility**: New message types (including those from add-ons) should be encrypted by default without code changes.

### Options considered

#### Option A — Extend protocol v2 with optional E2E fields (no version bump)

Add `e2e_pubkey` and `e2e_data` as new message types within the existing v2 protocol.
The server already forwards unrecognized message types, so no server changes would be needed at all.
Clients would negotiate E2E by exchanging pubkeys after joining a channel, without any server awareness.

**Advantages:**

* Zero server changes — works with existing relay servers today.
* No protocol version bump — simpler versioning.

**Disadvantages:**

* The server cannot report whether peers support E2E (no `e2e_supported` field in client info), so clients cannot know whether E2E is possible until they wait and see if a pubkey arrives. This creates a race condition: do you warn the user after 5 seconds of no pubkey? What if the peer is just slow?
* The server cannot report whether it allows E2E (`e2e_available`), so the direct-connection server cannot signal that E2E is unnecessary.
* No `user_id` in `channel_joined` — clients cannot know their own ID, which is needed for the `to` field in encrypted messages. Without it, clients cannot filter messages addressed to them in multi-peer channels.
* Future capabilities beyond E2E would also lack a clean signaling mechanism.

#### Option B — Protocol v3 with server-side capability signaling (proposed)

Bump the protocol version to 3.
The server derives `e2e_supported` from the protocol version and includes it in client info.
The server also reports `e2e_available` (a server-level configuration flag) and `user_id` in `channel_joined`.
Clients use these signals to decide whether to initiate E2E, with no race conditions or timeouts.

**Advantages:**

* Clean capability negotiation — clients know immediately whether E2E is possible.
* `user_id` enables addressed encryption (`to` field) for multi-peer channels.
* Extensible — v3 can gate future capabilities without another version bump.
* Small, well-defined server changes (~30 lines in the Python relay, already implemented in the Rust relay).

**Disadvantages:**

* Requires relay server update (though minimal and backward compatible).

#### Option C — Status quo (no E2E)

Do not add E2E encryption. Relay connections continue to be readable by anyone with server access.

**Advantages:**

* No implementation effort. No new dependencies. No risk of crypto bugs.

**Disadvantages:**

* Users must fully trust relay operators and server security with all session data, including keystrokes and clipboard content.
* No path to verifiable privacy for relay connections.
* In compliance-sensitive, professional, or enterprise settings where relay privacy is a hard requirement, users may fall back to generic remote access solutions — for example, Windows Remote Desktop (RDP) with the [rdAccess add-on](https://github.com/LeonarddeR/rdAccess), which provides a fully encrypted point-to-point connection where NVDA runs on the remote machine and speech/braille are tunneled to the local instance. However, these solutions require the remote machine to be directly reachable (no NAT traversal or relay), involve more infrastructure (firewall rules, VPN, or port forwarding), and lack the simplicity of NVDA Remote's channel-based model where two users just share a key and connect through a relay. NVDA Remote with E2E would bring that same level of privacy without sacrificing ease of use.

### Proposed technical design

#### How E2E encryption works at a high level

The core idea is that two clients can agree on a shared secret over an untrusted network — without ever sending that secret across the wire. This is achieved using Diffie-Hellman (DH) key exchange: each client generates a keypair (a private key that stays local and a public key that is shared), and then combines its own private key with the other client's public key to derive the same shared secret independently. Anyone observing the exchange — including the relay server — sees only the public keys, which are useless without the corresponding private key. Once both sides have the shared secret, all session data is encrypted with it: the relay server forwards ciphertext it cannot decrypt.

The key insight of this design is that the channel key — which both parties already know but the relay server should not — is mixed into the key derivation. This means that even if a malicious relay operator intercepts the public key exchange and substitutes their own keys (a man-in-the-middle attack), the resulting shared secrets would not match because the operator does not know the real channel key. The attack is cryptographically impossible, not just detectable.

To keep the real channel key hidden from the server, clients send a hash of the channel key in the `JOIN` message instead of the key itself. The server uses this hash purely as a routing label to group clients into channels — it does not need the real key.

#### Protocol changes

The protocol version would be bumped from 2 to 3.
Two new message types would be added:

* `e2e_pubkey` — broadcast by each client after joining, carries the ephemeral X25519 public key and a nonce prefix.
* `e2e_data` — encrypted data-plane message addressed to a specific peer.

The `JOIN` message would send a SHA-256 hash of the channel key instead of the raw key. The server uses this hash as the channel routing label. Since the server treats the channel key as an opaque string, this requires no server-side changes — the hash is just a different string.

**Backwards compatibility:** E2E clients and non-E2E clients cannot join the same channel — the hashed and raw channel keys are different strings, so the server routes them to separate channels. This is intentional: mixed plaintext/E2E channels would defeat the purpose of E2E since the server could read traffic to/from the plaintext peer. A user setting to disable E2E would let users connect to old servers or peers when needed (see below).

#### Relay server changes

The relay server would need three small, additive changes (no new dependencies, no cryptographic code):

1. **Add `e2e_supported` to client info**: Derived from the client's protocol version (>= 3). Included in join/leave notifications and the channel member list.

2. **Add `user_id` to the channel join response**: The client's own assigned ID. In v2, clients have no way to learn their own ID — they only see other clients' IDs in `origin` fields. E2E requires addressed encryption: the `e2e_data` message includes a `to` field so only the intended recipient decrypts it, and the receiver verifies that the inner `_from` matches the outer `origin`. Both of these require clients to know their own ID.

3. **Add `e2e_available` to the channel join response**: A server-level boolean flag (default true). The protocol supports operators disabling E2E by setting this to `false` — for example, to run a debugging or monitoring relay where traffic inspection is required, to operate a relay for automated testing where encryption overhead is undesirable, or to comply with organizational policies that require server-side logging. Server implementations are free to expose this as a configuration option or hardcode it to the default. When `e2e_available` is `false`, v3 clients must not initiate E2E and should always warn the user that the session is not end-to-end encrypted.

The server would not parse `e2e_pubkey` or `e2e_data` — they would be unknown message types that pass through the existing opaque relay path. The total change is minimal and fully backward compatible with v2 clients.

These v3 changes are already implemented in the [Rust relay server](https://github.com/ragb/nvda-remote-server-rs). The Python relay server (nvaccess/remote-server) would still need them — approximately 20-30 lines of Python, no new dependencies, no cryptographic code.

#### Cryptographic design

* **Channel key hashing**: The real channel key is never sent to the server. Clients compute `SHA-256(channel_key)` and send the hex digest in the `JOIN` message. The server uses it as an opaque routing label. This prevents the relay operator from learning the channel key. Note that the existing `generate_key` server message (where the server generates a channel key for the client) is incompatible with E2E — if the server generates the key, it knows it, defeating channel key hashing. When E2E is enabled, clients must generate channel keys locally (e.g. random hex string). The `generate_key` message remains available for non-E2E scenarios.
* **Ephemeral session key**: Each session would generate a fresh X25519 keypair for encryption. PyNaCl's `nacl.public.PrivateKey` / `PublicKey`. Keys are discarded when the session ends — there is no persistent key material.
* **Key exchange with channel key binding**: The `e2e_pubkey` message would include the ephemeral X25519 public key and a nonce prefix. After receiving a peer's public key, each client derives the pairwise shared secret using X25519 DH, then feeds the result through HKDF with the real channel key as salt: `HKDF(ikm=DH_shared_secret, salt=channel_key, info=b"nvda-remote-e2e")`. This binds the session key to the channel key — a man-in-the-middle who does not know the real channel key derives a different session key, causing all encrypted messages to fail decryption on both sides. The attack is self-revealing and useless.
* **Authenticated encryption**: XSalsa20-Poly1305 (NaCl `crypto_box`). Each data-plane message would be encrypted separately for each peer with a unique nonce. The Poly1305 MAC ensures integrity and authenticity — tampered ciphertexts would be rejected.
* **Per-peer encryption (no broadcast)**: Each data-plane message would be encrypted separately for each peer, producing one `e2e_data` message per recipient. This means a client with N peers sends N encrypted copies of each message. With the typical 2-4 clients in NVDA Remote channels this is negligible, but it is a deliberate tradeoff: pairwise encryption avoids the complexity of group key agreement while giving each peer its own shared secret and nonce space. The relay server already forwards messages individually per client, so this aligns with the existing relay model.
* **No persistent keys or trust stores**: There are no persistent identity keys, no TOFU (Trust On First Use), and no fingerprint verification. The channel key itself — already a shared secret between the parties — provides the authentication. This dramatically simplifies both the implementation and the user experience: there are no security dialogs to understand, no identity-changed warnings, and no persistent state to manage across sessions.

#### Why no TOFU or identity keys?

An earlier iteration considered persistent identity keys with Trust On First Use (TOFU), as in SSH. However, TOFU trusts whatever it sees on the first connection — a malicious relay operator who intercepts the very first key exchange is never detected. Channel key hashing eliminates this vulnerability entirely: the channel key is already a shared secret that the relay does not know (after hashing), and mixing it into the key derivation makes MITM cryptographically impossible from the first connection. This is strictly stronger than TOFU, with far less code and no user-facing complexity.

#### Protocol flow

A complete E2E session between two clients (A = leader, B = follower) through a v3 relay would proceed as follows:

1. **Connection**: Both clients connect via TLS and send `protocol_version: 3`. The server records them as v3 (and therefore `e2e_supported: true`).

2. **Channel join**: Client A computes `SHA-256(channel_key)` and sends the hash in the `join` message. The server uses this hash as the channel routing label. The server responds with `channel_joined` containing `e2e_available: true`, `user_id` (A's assigned ID), and a list of existing clients (empty if A is first).

3. **Second client joins**: Client B computes the same hash (it knows the same channel key) and sends `join`. The server matches the hash and places B in the same channel. The server responds to B with `channel_joined` listing A as an existing client with `e2e_supported: true`. The server also sends `client_joined` to A with B's info.

4. **E2E init**: Both clients see that the server supports E2E and all peers are v3. Each creates an E2E session, generating an ephemeral X25519 keypair.

5. **Key exchange**: Each client broadcasts an `e2e_pubkey` message containing the ephemeral X25519 public key and a nonce prefix. The server relays these opaquely with `origin` added. Each receiving client performs X25519 DH and derives the session key via `HKDF(DH_shared_secret, channel_key)`.

6. **Encrypted data**: All data-plane messages (keystrokes, speech, braille, clipboard) would be encrypted per-peer using XSalsa20-Poly1305 with the HKDF-derived key. Each encrypted message (`e2e_data`) would be addressed to a specific recipient via the `to` field. The server relays these as opaque blobs.

7. **Teardown**: On disconnect, ephemeral keys would be discarded. There is no persistent state — the next session starts fresh with new ephemeral keys.

#### Encryption in the client

The session layer would transparently encrypt data-plane messages when E2E is active.
A control-plane blacklist would define message types that must NOT be encrypted (the server needs to parse them: protocol version, join, channel notifications, etc.).
All other message types — including any new ones added by future code or extensions — would be encrypted by default.
This is intentionally a blacklist rather than a whitelist so that new message types get encryption for free.

#### Direct connections

The built-in direct-connection server would set `e2e_available: false` in its channel join response.
This would tell the client not to initiate E2E — the point-to-point TLS tunnel is already private.
No other changes would be needed for direct connections.

#### User setting to disable E2E

Because channel key hashing means E2E clients and non-E2E clients cannot join the same channel, a user setting to disable E2E would be provided. When disabled, the client would send the raw channel key in `JOIN` (v2 behavior) and not initiate E2E. This allows connecting to old servers or peers running older NVDA versions. The user would be warned that the session is not end-to-end encrypted.

#### Why not Signal Protocol or Noise Framework?

This design uses the same cryptographic primitives as Signal and Noise (X25519, authenticated encryption) but is intentionally much simpler. Both Signal and Noise solve harder problems that do not apply to a real-time screen reader relay with 2-4 simultaneous online clients:

* **No X3DH** (Signal): Single X25519 DH with channel key binding is sufficient since both peers are online and share a pre-existing secret.
* **No Double Ratchet** (Signal): Per-session forward secrecy is adequate. If an attacker can read session keys from client memory, they can already read the screen reader output directly.
* **No identity keys or TOFU** (Signal/SSH): Signal uses a central key server; SSH uses TOFU. We use the channel key — already a shared secret — mixed into the key derivation. This provides cryptographic MITM protection from the first connection, unlike TOFU which is vulnerable on first use.
* **Pairwise keys, not group keys** (Signal): 2-4 clients means O(n^2) pairwise keys is fine.
* **No Noise framework**: Noise's `XX` pattern provides identity hiding and formally verified handshakes, but at significant cost:
  * The `noiseprotocol` Python library is much less mature and less widely deployed than PyNaCl.
  * Noise's transport model assumes a byte stream, not JSON-over-lines — adapting it to the NVDA Remote relay protocol would require a framing layer that adds complexity for no security benefit.
  * The security properties are equivalent for our threat model: both use X25519 DH with authenticated encryption. Our design has the additional advantage of channel key binding, which Noise would need to be configured for.

### Proposed decision and rationale

**Option B — Protocol v3 with server-side capability signaling** is the proposed approach.

The key advantage over Option A (extending v2) is clean capability negotiation: the server tells clients immediately whether E2E is possible, eliminating race conditions and enabling clear user warnings.
The server changes are minimal (~30 lines of Python, no crypto), fully backward compatible, and already proven in the Rust relay implementation.

Option C (status quo) leaves relay users with no privacy from anyone with server access.
Using heavier frameworks like Signal Protocol or Noise would add unnecessary complexity for the same underlying primitives (see "Why not Signal Protocol or Noise Framework?" above).

### Impact analysis

**Positive:**

* Neither relay server operators nor anyone who compromises the server can read session content (keystrokes, speech, braille, clipboard) when E2E is active. This also reduces liability for operators.
* **Cryptographic MITM protection from the first connection** — unlike TOFU-based designs, a malicious relay operator cannot perform a man-in-the-middle attack because the channel key (which they never see) is mixed into the key derivation. This is the strongest guarantee achievable without a central authority.
* Per-session forward secrecy via ephemeral keys — there are no persistent keys to compromise.
* No user-facing security decisions — no trust dialogs, no identity warnings, no fingerprint verification. E2E either works or the user is told it's unavailable.
* Users are warned when E2E is not available, enabling informed consent.
* Add-on developers get encryption for custom message types automatically.

**Neutral:**

* Direct connections are unaffected — no behavior change, no additional overhead.
* V2 servers continue to work (clients fall back to plaintext with a warning). V2 clients on v3 servers are reported as non-E2E peers.

**Negative:**

* **E2E clients and non-E2E clients cannot share a channel.** Channel key hashing means the server sees different routing labels from old and new clients. This is intentional (mixed channels defeat E2E) but means users connecting to old peers must disable E2E via the user setting.
* New dependency: PyNaCl (~1.3 MB, wraps libsodium). Bundled into the NVDA binary — no impact on end-user installation. Well-maintained and widely used.
* Slight per-message overhead from encryption/decryption. For the volume of messages in a screen reader relay (tens per second at most), this is negligible.

**API/add-on compatibility:**

* No breaking changes. The remote message type enum gains two new members for E2E.
* The session layer transparently handles encryption — existing message sending for control-plane messages is unaffected.
* New extension points allow add-ons to react to E2E status changes (unavailable, established, torn down).

### Architecture and code change plan

**NVDA client:**

* Protocol module: bump version to 3, add E2E message types
* New E2E module: ephemeral session key (X25519) management, key exchange with channel key binding (HKDF), encrypt/decrypt
* Session layer: channel key hashing in JOIN, transparent encryption in send path, E2E lifecycle management, warning extension points, user setting for disabling E2E
* Client layer: route data-plane sends through session, wire up E2E warning handlers
* Dialogs: warning dialogs for E2E unavailable
* Direct-connection server: add `user_id` and `e2e_available` to channel join response

**Relay server:**

* Add `e2e_supported` to client info, `user_id` and `e2e_available` to channel join response
* Tests for v3 fields

**Documentation:**

* Full protocol specification (v1-v3)
* User-facing "Connection protection" section in the user guide
* Release notes

**Tests:**

* Unit tests for E2E crypto: key exchange with HKDF, encrypt/decrypt round-trips, channel key mismatch rejection, error cases

### Integration plan

The work is split into independently reviewable PRs:

1. **Relay server PR** (nvaccess/remote-server): Add v3 fields to channel join response and client notifications. No crypto, no new dependencies. Fully backward compatible.

2. **Protocol spec PR** (nvaccess/nvda): Document the full protocol (v1-v3), covering the existing v1/v2 protocol as well as the v3 E2E additions. No code changes. Establishes the specification that implementation PRs follow.

3. **Crypto module PR**: E2E encryption module (ephemeral key exchange, HKDF with channel key, encrypt/decrypt) + unit tests. Self-contained with no session integration yet. Add PyNaCl dependency. Reviewable in isolation.

4. **Session integration + UX PR**: Wire the E2E module into the session layer — channel key hashing in JOIN, transparent encryption, lifecycle management, inbound handlers, warning dialogs (E2E unavailable), user setting to disable E2E, user documentation.

**Dependency order:** PRs 1 and 2 can proceed in parallel — the relay server changes are independent of the protocol spec. PR 3 depends on the protocol spec being agreed (PR 2) but not on the relay server (PR 1). PR 4 depends on PR 3.

**Merge strategy:** Each PR merges to `master` independently.

**Rollback strategy:** Each PR is independently revertable. If E2E is found to have issues after merging:

* Revert the session integration PR (PR 4) — disables E2E while keeping the crypto module and protocol spec.
* The relay server changes (PR 1) are harmless without the client — they just add unused fields.

### Risks and mitigations

* **Crypto implementation bug** — Likelihood: low (using PyNaCl's high-level API, not raw primitives). Impact: high (false sense of security). Mitigation: unit tests covering key exchange, HKDF derivation, encrypt/decrypt round-trips, tampered ciphertext rejection, channel key mismatch detection. External security review recommended before release.

* **Relay server operators slow to update** — Likelihood: medium (community servers may lag). Impact: low (users warned, can connect with E2E disabled). E2E is on by default — users are warned when unavailable and can disable E2E to connect to old servers.

* **Long-term maintenance burden** — Likelihood: high (crypto code lives indefinitely). Impact: medium (subtle bugs, stale dependencies). Cryptographic code is harder to modify safely than typical application logic — even small changes to key derivation, nonce handling, or serialization can silently break security without failing any functional tests. PyNaCl/libsodium updates may introduce breaking API changes or deprecations. Mitigation: thorough documentation (this ADR, protocol spec, inline comments on security-critical paths), comprehensive unit tests that verify cryptographic properties (not just happy-path round-trips), and treating any change to the E2E module as security-sensitive during code review. The simplified design (no persistent keys, no TOFU, no identity management) significantly reduces the maintenance surface compared to earlier iterations.

### Validation and success criteria

**Automated tests:**

* Unit tests for the E2E module: key exchange with HKDF, channel key binding verification (mismatched keys fail), encrypt/decrypt round-trips, preserialized speech messages, multi-peer pairwise encryption, error cases (unknown peer, tampered ciphertext, wrong nonce).
* Integration tests for relay server v3 fields.

**Manual test scenarios:**

* Two v3 clients through a v3 relay — E2E established, data encrypted.
* Two v3 clients through a v2 relay — E2E not available, user warned.
* V3 client with E2E disabled through a v3 relay — connects to channel using raw key, warned about no E2E.
* Direct connection — no E2E, no warnings, behavior unchanged.
* Channel key mismatch — clients with different channel keys land on different channels (verify routing).

**Success criteria:**

* All data-plane messages are encrypted when E2E is active (verifiable by inspecting relay server logs — only `e2e_data` messages visible, no plaintext content).
* The relay server never sees the real channel key (only the SHA-256 hash).
* No regressions in v2 server behavior (v3 fields are additive).
* Warning dialogs are accessible (speech + braille).
* Per-server trust suppression for E2E unavailable warnings works correctly.

### Open questions

1. **Relay server update timing**: Should the nvaccess/remote-server be updated before or in parallel with the NVDA client changes? The client gracefully handles servers that don't support v3, so either order works. Updating the server first is lower risk.

2. **Follower control password**: The follower (controlled machine) could require an additional password that the leader must send over the established E2E channel before any commands are accepted. This would be a local setting on the follower — no protocol or server changes needed. It provides defense in depth against someone who has the channel key but should not be controlling the machine (e.g. leaked key, shared channel). Simple for users to understand and adds a meaningful layer of access control.

3. **Security audit**: Should the cryptographic design be reviewed by an external security expert before merging? The primitives are standard and well-understood, but the protocol composition and implementation could benefit from expert review.
