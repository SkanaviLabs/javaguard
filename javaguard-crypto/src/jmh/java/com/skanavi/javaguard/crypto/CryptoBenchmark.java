// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class CryptoBenchmark {
  @Param({"64", "1420"})
  int size;

  private final ChaCha20Poly1305 aead = new ChaCha20Poly1305();
  private SecretKey key;
  private byte[] packet;
  private byte[] sealed;
  private long counter;
  private byte[] privateKey;
  private byte[] peerPublicKey;

  @Setup
  public void setup() {
    SecureRandom random = new SecureRandom();
    byte[] k = new byte[32];
    random.nextBytes(k);
    key = ChaCha20Poly1305.key(k);
    packet = new byte[size + ChaCha20Poly1305.TAG_LENGTH];
    sealed = aead.seal(key, 0, new byte[size], null);
    privateKey = X25519.generatePrivateKey(random);
    peerPublicKey = X25519.publicKey(X25519.generatePrivateKey(random));
  }

  @Benchmark
  public int chachaSealInPlace() {
    return aead.seal(key, ++counter, packet, 0, size, packet, 0, null);
  }

  @Benchmark
  public byte[] chachaOpen() throws AEADBadTagException {
    return aead.open(key, 0, sealed, null);
  }

  @Benchmark
  public byte[] blake2sHash() {
    return new Blake2s(32).update(packet, 0, size).digest();
  }

  @Benchmark
  public byte[] x25519SharedSecret() throws Exception {
    return X25519.sharedSecret(privateKey, peerPublicKey);
  }
}
