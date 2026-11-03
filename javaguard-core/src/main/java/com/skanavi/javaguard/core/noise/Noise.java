// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

import static com.skanavi.javaguard.crypto.Blake2s.hash;

import com.skanavi.javaguard.core.noise.Handshake.State;
import com.skanavi.javaguard.crypto.ChaCha20Poly1305;
import com.skanavi.javaguard.crypto.Kdf;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.crypto.Tai64n;
import com.skanavi.javaguard.crypto.X25519;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Function;
import javax.crypto.AEADBadTagException;

/**
 * The {@code Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s} handshake as specified in section 5.4 of the
 * WireGuard whitepaper.
 *
 * <p>Initiator: {@link #createInitiation}, then {@link #consumeResponse}, then {@link
 * #beginSession}. Responder: {@link #consumeInitiation}, then {@link #createResponse}, then {@link
 * #beginSession}. mac1/mac2 are handled separately by {@link CookieGenerator} (outgoing) and {@link
 * CookieChecker} (incoming), which must vet messages before they reach this class.
 *
 * <p>Thread-safe. Each {@link Handshake} serializes its own transitions.
 */
public final class Noise {
  private static final byte[] EMPTY = new byte[0];

  final StaticIdentity identity;
  final IndexTable indices;
  final TimeSource time;
  private final SecureRandom random;

  /** Creates an engine using the system clocks and a fresh {@link SecureRandom}. */
  public Noise(StaticIdentity identity, IndexTable indices) {
    this(identity, indices, TimeSource.system(), new SecureRandom());
  }

  /** Creates an engine with explicit time and randomness, for tests and simulation. */
  public Noise(StaticIdentity identity, IndexTable indices, TimeSource time, SecureRandom random) {
    this.identity = identity;
    this.indices = indices;
    this.time = time;
    this.random = random;
  }

  /** The local identity. */
  public StaticIdentity identity() {
    return identity;
  }

  /**
   * Creates handshake state for a peer.
   *
   * @throws InvalidKeyException if {@code remoteStatic} is a small-order point
   * @throws IllegalArgumentException if {@code remoteStatic} is our own public key
   */
  public Handshake newHandshake(PublicKey remoteStatic, PresharedKey presharedKey)
      throws InvalidKeyException {
    if (remoteStatic.equals(identity.publicKey())) {
      throw new IllegalArgumentException("peer public key equals the local public key");
    }
    byte[] ss = X25519.sharedSecret(identity.privateBytes, remoteStatic.toBytes());
    return new Handshake(this, remoteStatic, presharedKey, ss);
  }

  /**
   * Starts a handshake with {@code hs}'s peer, abandoning any handshake in progress. The result
   * still needs mac1/mac2 from {@code hs.cookieGenerator()}.
   */
  public HandshakeInitiation createInitiation(Handshake hs) {
    checkOwned(hs);
    HandshakeInitiation msg = HandshakeInitiation.create();
    var aead = new ChaCha20Poly1305();
    hs.lock.lock();
    try {
      hs.zero();
      byte[] h = hs.initiatorInitialHash;
      byte[] ck = Protocol.INITIAL_CHAIN_KEY;

      byte[] ephemeral = X25519.generatePrivateKey(random);
      byte[] ephemeralPub = X25519.publicKey(ephemeral);
      ck = Kdf.kdf1(ck, ephemeralPub);
      msg.ephemeral(ephemeralPub);
      h = hash(h, ephemeralPub);

      byte[][] ckKey = Kdf.kdf2(ck, dh(ephemeral, hs.remoteStaticBytes));
      byte[] encStatic = aead.seal(ckKey[1], 0, identity.publicBytes, h);
      msg.encryptedStatic(encStatic);
      h = hash(h, encStatic);

      ckKey = Kdf.kdf2(ckKey[0], hs.staticStatic);
      byte[] encTimestamp = aead.seal(ckKey[1], 0, Tai64n.encodeWhitened(time.now()), h);
      msg.encryptedTimestamp(encTimestamp);
      h = hash(h, encTimestamp);

      hs.localIndex = indices.allocate(hs);
      msg.sender(hs.localIndex);
      hs.hash = h;
      hs.chainKey = ckKey[0];
      hs.localEphemeral = ephemeral;
      hs.state = State.INITIATION_CREATED;
      return msg;
    } catch (InvalidKeyException e) {
      // Only reachable if the peer's static key is small-order, which newHandshake rejects.
      hs.zero();
      throw new IllegalStateException(e);
    } finally {
      hs.lock.unlock();
    }
  }

  /**
   * Processes an initiation addressed to us. Decrypts the initiator's static key, finds its state
   * through {@code peers}, and checks the timestamp against replays and floods.
   *
   * @param peers looks up configured peers by static public key; returns {@code null} if unknown
   * @return the peer's handshake, now in {@link State#INITIATION_CONSUMED}, or {@code null} if the
   *     message is invalid, from an unknown peer, replayed, or arrived too soon after the last one
   */
  public Handshake consumeInitiation(
      HandshakeInitiation msg, Function<PublicKey, Handshake> peers) {
    var aead = new ChaCha20Poly1305();
    try {
      byte[] h = identity.responderInitialHash;
      byte[] ck = Protocol.INITIAL_CHAIN_KEY;

      byte[] ephemeralPub = msg.ephemeral();
      ck = Kdf.kdf1(ck, ephemeralPub);
      h = hash(h, ephemeralPub);

      byte[][] ckKey = Kdf.kdf2(ck, dh(identity.privateBytes, ephemeralPub));
      byte[] encStatic = msg.encryptedStatic();
      byte[] staticBytes = aead.open(ckKey[1], 0, encStatic, h);
      h = hash(h, encStatic);

      Handshake hs = peers.apply(PublicKey.fromBytes(staticBytes));
      if (hs == null || hs.noise != this) {
        return null;
      }

      ckKey = Kdf.kdf2(ckKey[0], hs.staticStatic);
      byte[] encTimestamp = msg.encryptedTimestamp();
      byte[] timestamp = aead.open(ckKey[1], 0, encTimestamp, h);
      h = hash(h, encTimestamp);

      long now = time.nanoTime();
      hs.lock.lock();
      try {
        if (!Tai64n.isAfter(timestamp, hs.latestTimestamp)) {
          return null; // replay
        }
        if (hs.consumedAnyInitiation
            && now - hs.lastInitiationConsumedNanos
                <= Protocol.HANDSHAKE_INITIATION_RATE.toNanos()) {
          return null; // flood
        }
        hs.zero();
        hs.latestTimestamp = timestamp;
        hs.lastInitiationConsumedNanos = now;
        hs.consumedAnyInitiation = true;
        hs.hash = h;
        hs.chainKey = ckKey[0];
        hs.remoteEphemeral = ephemeralPub;
        hs.remoteIndex = msg.sender();
        hs.state = State.INITIATION_CONSUMED;
        return hs;
      } finally {
        hs.lock.unlock();
      }
    } catch (InvalidKeyException | AEADBadTagException e) {
      return null;
    }
  }

  /**
   * Answers a consumed initiation. The result still needs mac1/mac2 from {@code
   * hs.cookieGenerator()}.
   *
   * @return the response, or {@code null} if {@code hs} is not in {@link State#INITIATION_CONSUMED}
   */
  public HandshakeResponse createResponse(Handshake hs) {
    checkOwned(hs);
    HandshakeResponse msg = HandshakeResponse.create();
    hs.lock.lock();
    try {
      if (hs.state != State.INITIATION_CONSUMED) {
        return null;
      }
      hs.localIndex = indices.allocate(hs);
      msg.sender(hs.localIndex);
      msg.receiver(hs.remoteIndex);

      byte[] ephemeral = X25519.generatePrivateKey(random);
      byte[] ephemeralPub = X25519.publicKey(ephemeral);
      msg.ephemeral(ephemeralPub);
      byte[] h = hash(hs.hash, ephemeralPub);
      byte[] ck = Kdf.kdf1(hs.chainKey, ephemeralPub);
      ck = Kdf.kdf1(ck, dh(ephemeral, hs.remoteEphemeral));
      ck = Kdf.kdf1(ck, dh(ephemeral, hs.remoteStaticBytes));

      byte[][] ckTauKey = Kdf.kdf3(ck, hs.presharedKey().toBytes());
      h = hash(h, ckTauKey[1]);
      byte[] encEmpty = new ChaCha20Poly1305().seal(ckTauKey[2], 0, EMPTY, h);
      msg.encryptedEmpty(encEmpty);
      h = hash(h, encEmpty);

      hs.hash = h;
      hs.chainKey = ckTauKey[0];
      hs.localEphemeral = ephemeral;
      hs.state = State.RESPONSE_CREATED;
      Arrays.fill(ckTauKey[1], (byte) 0);
      Arrays.fill(ckTauKey[2], (byte) 0);
      return msg;
    } catch (InvalidKeyException e) {
      // consumeInitiation already rejected small-order ephemerals; treat as invalid.
      hs.zero();
      return null;
    } finally {
      hs.lock.unlock();
    }
  }

  /**
   * Processes a response to an initiation we sent, found through its receiver index.
   *
   * @return the handshake, now in {@link State#RESPONSE_CONSUMED}, or {@code null} if no initiation
   *     of ours matches or the message does not authenticate
   */
  public Handshake consumeResponse(HandshakeResponse msg) {
    if (!(indices.get(msg.receiver()) instanceof Handshake hs) || hs.noise != this) {
      return null;
    }
    hs.lock.lock();
    try {
      if (hs.state != State.INITIATION_CREATED || hs.localIndex != msg.receiver()) {
        return null;
      }
      byte[] ephemeralPub = msg.ephemeral();
      byte[] h = hash(hs.hash, ephemeralPub);
      byte[] ck = Kdf.kdf1(hs.chainKey, ephemeralPub);
      ck = Kdf.kdf1(ck, dh(hs.localEphemeral, ephemeralPub));
      ck = Kdf.kdf1(ck, dh(identity.privateBytes, ephemeralPub));

      byte[][] ckTauKey = Kdf.kdf3(ck, hs.presharedKey().toBytes());
      h = hash(h, ckTauKey[1]);
      byte[] encEmpty = msg.encryptedEmpty();
      new ChaCha20Poly1305().open(ckTauKey[2], 0, encEmpty, h);
      h = hash(h, encEmpty);

      Arrays.fill(hs.localEphemeral, (byte) 0);
      hs.localEphemeral = null;
      hs.hash = h;
      hs.chainKey = ckTauKey[0];
      hs.remoteIndex = msg.sender();
      hs.state = State.RESPONSE_CONSUMED;
      return hs;
    } catch (InvalidKeyException | AEADBadTagException e) {
      return null;
    } finally {
      hs.lock.unlock();
    }
  }

  /**
   * Derives transport keys from a finished handshake and resets it. The handshake's local index is
   * transferred to the returned keypair in the {@link IndexTable}.
   *
   * @return the keypair, or {@code null} if {@code hs} is not in {@link State#RESPONSE_CONSUMED}
   *     (initiator) or {@link State#RESPONSE_CREATED} (responder)
   */
  public Keypair beginSession(Handshake hs) {
    checkOwned(hs);
    hs.lock.lock();
    try {
      boolean initiator;
      if (hs.state == State.RESPONSE_CONSUMED) {
        initiator = true;
      } else if (hs.state == State.RESPONSE_CREATED) {
        initiator = false;
      } else {
        return null;
      }
      byte[][] keys = Kdf.kdf2(hs.chainKey, EMPTY);
      byte[] send = initiator ? keys[0] : keys[1];
      byte[] receive = initiator ? keys[1] : keys[0];
      Keypair keypair =
          new Keypair(
              ChaCha20Poly1305.key(send),
              ChaCha20Poly1305.key(receive),
              hs.localIndex,
              hs.remoteIndex,
              initiator,
              time.nanoTime());
      Arrays.fill(keys[0], (byte) 0);
      Arrays.fill(keys[1], (byte) 0);
      if (!indices.replace(hs.localIndex, hs, keypair)) {
        throw new IllegalStateException("handshake index was released unexpectedly");
      }
      hs.localIndex = 0; // now owned by the keypair
      hs.zero();
      return keypair;
    } finally {
      hs.lock.unlock();
    }
  }

  private static byte[] dh(byte[] privateKey, byte[] publicKey) throws InvalidKeyException {
    return X25519.sharedSecret(privateKey, publicKey);
  }

  private void checkOwned(Handshake hs) {
    if (hs.noise != this) {
      throw new IllegalArgumentException("handshake belongs to a different Noise instance");
    }
  }
}
