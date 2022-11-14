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
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.rcat.error.RcatDecryptionException;
import com.google.rcat.error.RcatExpiredException;
import com.google.rcat.error.RcatInvalidContentBindingException;
import com.google.rcat.error.RcatParsingException;
import com.google.rcat.error.RcatSignatureValidationException;
import com.google.rcat.error.RcatUnknownIssuerIdException;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import com.google.rcat.proto.RandomizedCounterAbuseTokenEnvelope;
import com.google.rcat.proto.RandomizedCounterAbuseTokenPayload;
import java.time.Instant;
import java.util.Map;

/**
 * RCAT Verifier (third-party).
 *
 * <p>Verifies RCATs and extracts the group ID.
 *
 * <p>Usage: Instance of {@code RcatVerifier} can be created with {@code RcatVerifier.Builder}.
 *
 * <pre>{@code
 * RcatVerifier verifier = RcatVerifier.builder()
 *     .setPartnerKeysetHandleMapping(...)
 *     .setPrivateKeysetHandle(...)
 *     .build();
 * }</pre>
 */
@CheckReturnValue
public final class RcatVerifier {

  private static final ExtensionRegistry DEFAULT_EXTENSION_REGISTRY =
      ExtensionRegistry.getEmptyRegistry();

  private final Map<Integer, RcatCrypto.Verifier> partnerRcatCryptoVerifierMapping;
  private final RcatCrypto.Decrypter decrypter;
  private final Instant instant;

  /**
   * Validates and decrypts a randomized counter-abuse token.
   *
   * <p>We decrypt the token before validating it. Once decrypted, we will verify the signature of
   * the payload and make sure that the content binding is correct.
   *
   * @param token an instance of RandomizedCounterAbuseToken to process.
   * @param contentId content to which the token is expected to be bound.
   * @param nonce client nonce or {@code RcatUtils.EMPTY_NONCE} for non-blinded / non-e2ee use case.
   * @return an 64-bit long group ID
   * @throws RcatDecryptionException if the ciphertext can not be decrypted.
   * @throws RcatParsingException if the token is malformed.
   * @throws RcatUnknownIssuerIdException if the issuer id that issued the token is unknown.
   * @throws RcatSignatureValidationException if the signature can not be verified.
   * @throws RcatInvalidContentBindingException if the content binding appears to be invalid.
   * @throws RcatExpiredException if the RCAT is expired.
   */
  public long validateToken(RandomizedCounterAbuseToken token, String contentId, byte[] nonce)
      throws RcatDecryptionException, RcatParsingException, RcatUnknownIssuerIdException,
          RcatSignatureValidationException, RcatInvalidContentBindingException,
          RcatExpiredException {
    /* The issuer signs the plaintext, and relays the signature alongside the ciphertext. This
     * requires us to decrypt the UNTRUSTED input before being able to validate the sender. This is
     * currently assumed to be safe, as the RCAT protos do not have nested maps (or other
     * opportunities for DDoS attacks), but is something we should keep in mind.
     */
    byte[] plaintext = this.decrypter.decrypt(token.getCiphertext().toByteArray(), new byte[0]);

    RandomizedCounterAbuseTokenEnvelope envelope;
    try {
      envelope =
          RandomizedCounterAbuseTokenEnvelope.parseFrom(plaintext, DEFAULT_EXTENSION_REGISTRY);
    } catch (InvalidProtocolBufferException e) {
      throw new RcatParsingException("Malformed RCAT token envelope.", e);
    }

    RcatCrypto.Verifier verifier =
        this.partnerRcatCryptoVerifierMapping.get(envelope.getIssuerId());
    if (verifier == null) {
      throw new RcatUnknownIssuerIdException("Unknown issuer id: " + envelope.getIssuerId() + ".");
    }

    // Check 2. Is the signature valid?
    verifier.verify(envelope.getSignature().toByteArray(), envelope.getPayload().toByteArray());

    // Check 3. Is the content binding correct?
    long expectedContentBinding = RcatUtils.computeContentBinding(contentId, nonce);
    RandomizedCounterAbuseTokenPayload payload;
    try {
      payload =
          RandomizedCounterAbuseTokenPayload.parseFrom(
              envelope.getPayload(), DEFAULT_EXTENSION_REGISTRY);
    } catch (InvalidProtocolBufferException e) {
      throw new RcatParsingException("Malformed RCAT payload.", e);
    }

    if (expectedContentBinding != payload.getContentBinding()) {
      throw new RcatInvalidContentBindingException(
          "Current content binding does not match expected content binding.");
    }

    // Check 4. Is the token expired?
    long currentTimestampInSecs = this.instant.getEpochSecond();
    if (payload.getExpirationUtcSec() <= currentTimestampInSecs) {
      throw new RcatExpiredException("RCAT token is expired.");
    }

    // If all checks pass, returns the group ID.
    return payload.getGroupId();
  }

  public static Builder builder() {
    return new AutoBuilder_RcatVerifier_Builder().setInstant(Instant.now());
  }

  /** Builder for RcatVerifier class. */
  @AutoBuilder(ofClass = RcatVerifier.class)
  public abstract static class Builder {
    /**
     * Sets a mapping of RcatCrypto.Verifier to perform public key signing operation for a given
     * issuerId.
     */
    public abstract Builder setPartnerRcatCryptoVerifierMapping(
        Map<Integer, RcatCrypto.Verifier> partnerRcatCryptoVerifierMapping);

    /** Sets an instance of RcatCrypto.Decrypter to perform decryption operation. */
    public abstract Builder setRcatCryptoDecrypter(RcatCrypto.Decrypter rcatCryptoDecrypter);

    /**
     * Sets instant for time reference.
     *
     * <p>Instant should be always set to .now() (its default value) and should only be set to
     * something else for test purposes, e.g.: expired token, ...
     */
    public abstract Builder setInstant(Instant instant);

    /**
     * Creates a new instance of RcatVerifier.
     *
     * @return a new instance of RcatVerifier.
     */
    public abstract RcatVerifier build();
  }

  RcatVerifier(
      Map<Integer, RcatCrypto.Verifier> partnerRcatCryptoVerifierMapping,
      RcatCrypto.Decrypter rcatCryptoDecrypter,
      Instant instant) {
    this.partnerRcatCryptoVerifierMapping = partnerRcatCryptoVerifierMapping;
    this.decrypter = rcatCryptoDecrypter;
    this.instant = instant;
  }
}
