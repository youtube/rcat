/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.rcat;

import com.google.auto.value.AutoBuilder;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.hash.Hashing;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.protobuf.ByteString;
import com.google.rcat.error.RcatEncryptionException;
import com.google.rcat.error.RcatSigningException;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import com.google.rcat.proto.RandomizedCounterAbuseTokenEnvelope;
import com.google.rcat.proto.RandomizedCounterAbuseTokenPayload;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;

/**
 * The issuer (first-party) generates RCATs that are sent to a Validator.
 *
 * <p>Issuers that are blinded to the content of their clients (e.g e2ee services) must compute the
 * content binding with a client nonce.
 *
 * <p>Usage: Instance of {@code RcatIssuer} can be created with {@code RcatIssuer.Builder}.
 *
 * <pre>{@code
 * RcatIssuer issuer = RcatIssuer.builder()
 *     .setMonthlySalt(...)
 *     .setIssuerId(...)
 *     .setRcatCryptoSigner(RcatTinkCrypto.Signer.withPrivateKeysetHandle(...))
 *     .setRcatCryptoEncrypter(RcatTinkCrypto.Encrypter.withPublicKeysetHandle(...))
 *     .setN(...)
 *     .setK(...)
 *     .build();
 * }</pre>
 */
@CheckReturnValue
public final class RcatIssuer {
  // Refer to the RCAT protocol explainer and adjust this value as needed for your environment and
  // use-cases (1 hour is a conservative lower-bound).
  private static final Duration DEFAULT_TOKEN_LIFETIME = Duration.ofHours(1);

  private final byte[] monthlySalt;
  private final int issuerId;
  private final int numberOfBuckets;
  private final Duration tokenLifetime;
  private final RcatCrypto.Signer signer;
  private final RcatCrypto.Encrypter encrypter;
  private final Instant instant;

  /**
   * Generates a randomized counter abuse token.
   *
   * <p>In the general case, we are not blinded to the content that the token is bound to, so we
   * compute the content binding (done on the client for e2ee) and then build the token just as we
   * do for e2ee.
   *
   * @param uid a byte representation of the user ID.
   * @param contentId ID of the content being bound.
   * @return an instance of RandomizedCounterAbuseToken containing the generated ciphertext.
   * @throws RcatSigningException if unable to sign the RCAT payload.
   * @throws RcatEncryptionException if unable to generate a ciphertext.
   */
  public RandomizedCounterAbuseToken generateToken(byte[] uid, String contentId)
      throws RcatSigningException, RcatEncryptionException {
    return this.generateTokenE2ee(
        uid, RcatUtils.computeContentBinding(contentId, RcatUtils.EMPTY_NONCE));
  }

  /**
   * Generates a randomized counter abuse token for the blinded e2ee use case.
   *
   * @param uid a byte representation of the user ID.
   * @param contentBinding client-provided content binding.
   * @return an instance of RandomizedCounterAbuseToken containing the generated ciphertext.
   * @throws RcatSigningException if unable to sign the RCAT payload.
   * @throws RcatEncryptionException if unable to generate a ciphertext.
   */
  public RandomizedCounterAbuseToken generateTokenE2ee(byte[] uid, long contentBinding)
      throws RcatSigningException, RcatEncryptionException {
    long expirationTimestampInSecs = this.instant.plus(this.tokenLifetime).getEpochSecond();
    RandomizedCounterAbuseTokenPayload payload =
        RandomizedCounterAbuseTokenPayload.newBuilder()
            .setGroupId(this.computeGroupId(uid))
            .setContentBinding(contentBinding)
            .setExpirationUtcSec(expirationTimestampInSecs)
            .build();
    byte[] payloadBytes = payload.toByteArray();

    // digital signature is encoded DER ASN.1 and Tink's wire format:
    // https://developers.google.com/tink/wire-format#digital_signatures
    byte[] cipherSignature = this.signer.sign(payloadBytes);

    RandomizedCounterAbuseTokenEnvelope envelope =
        RandomizedCounterAbuseTokenEnvelope.newBuilder()
            .setIssuerId(this.issuerId)
            .setSignature(ByteString.copyFrom(cipherSignature))
            .setPayload(ByteString.copyFrom(payloadBytes))
            .build();

    // ciphertext uses Tink's wire format:
    // https://developers.google.com/tink/wire-format#hybrid_public_key_encryption_hpke
    byte[] ciphertext = this.encrypter.encrypt(envelope.toByteArray(), new byte[0]);

    return RandomizedCounterAbuseToken.newBuilder()
        .setCiphertext(ByteString.copyFrom(ciphertext))
        .build();
  }

  public static Builder builder() {
    return new AutoBuilder_RcatIssuer_Builder()
        .setTokenLifetime(DEFAULT_TOKEN_LIFETIME)
        .setInstant(Instant.now());
  }

  /** Builder for RcatIssuer class. */
  @AutoBuilder(ofClass = RcatIssuer.class)
  public abstract static class Builder {
    /**
     * Sets 32 bytes monthly salt that is used for group ID calculation. The salt should be rotated
     * on a monthly basis.
     */
    public abstract Builder setMonthlySalt(byte[] monthlySalt);

    /** Sets issuer ID, an unique identifier assigned to the issuer out of band. */
    public abstract Builder setIssuerId(int issuerId);

    /** Sets an instance of RcatCrypto.Signer to perform public key signing operation. */
    public abstract Builder setRcatCryptoSigner(RcatCrypto.Signer signer);

    /** Sets an instance of RcatCrypto.Encrypter to perform encryption operation. */
    public abstract Builder setRcatCryptoEncrypter(RcatCrypto.Encrypter encrypter);

    /** Sets N, numbers of users to be assigned to groups. */
    public abstract Builder setN(int n);

    /** Sets K, target number of users per group. */
    public abstract Builder setK(int k);

    /** Sets the lifetime of the token. */
    public abstract Builder setTokenLifetime(Duration tokenLifetime);

    /**
     * Sets instant for time reference.
     *
     * <p>Instant should be always set to .now() (its default value) and should only be set to
     * something else for test purposes, e.g.: expired token...
     */
    public abstract Builder setInstant(Instant instant);

    /**
     * Creates a new instance of RcatIssuer.
     *
     * @return a new instance of RcatIssuer.
     * @throws InstantiationException if initialization has failed (e.g.: salt too small).
     * @throws GeneralSecurityException if can not create a signer and encrypter instance from given
     *     private and public keyset handles.
     */
    public abstract RcatIssuer build() throws InstantiationException, GeneralSecurityException;
  }

  /**
   * Computes the group ID for a given user ID.
   *
   * @param uid a byte representation of the user ID (e.g. UTF-8 codepoints)
   * @return an 64-bit long group ID
   */
  @VisibleForTesting
  public long computeGroupId(byte[] uid) {
    byte[] digest = Hashing.hmacSha256(this.monthlySalt).hashBytes(uid).asBytes();
    return new BigInteger(1, digest).mod(BigInteger.valueOf(this.numberOfBuckets)).longValue();
  }

  RcatIssuer(
      byte[] monthlySalt,
      int issuerId,
      RcatCrypto.Signer rcatCryptoSigner,
      RcatCrypto.Encrypter rcatCryptoEncrypter,
      int n,
      int k,
      Duration tokenLifetime,
      Instant instant) {
    if (monthlySalt.length != 32) {
      throw new IllegalArgumentException("monthlySalt must be 32 bytes.");
    }
    this.monthlySalt = monthlySalt;
    this.issuerId = issuerId;

    if (n < 1) {
      throw new IllegalArgumentException("number of users to assign should be at least 1.");
    }
    if (k < 1) {
      throw new IllegalArgumentException("number of users per group should be at least 1.");
    } else if (n < k) {
      throw new IllegalArgumentException(
          "number of users to assign should be greater than the number of users per group.");
    }
    this.numberOfBuckets = n / k;
    this.tokenLifetime = tokenLifetime;
    this.signer = rcatCryptoSigner;
    this.encrypter = rcatCryptoEncrypter;
    this.instant = instant;
  }
}
