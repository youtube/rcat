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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.protobuf.ByteString;
import com.google.rcat.error.RcatDecryptionException;
import com.google.rcat.error.RcatExpiredException;
import com.google.rcat.error.RcatInvalidContentBindingException;
import com.google.rcat.error.RcatParsingException;
import com.google.rcat.error.RcatSignatureValidationException;
import com.google.rcat.error.RcatUnknownIssuerIdException;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import com.google.rcat.proto.RandomizedCounterAbuseTokenEnvelope;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests error handling for anticipated failure scenarios. */
@RunWith(JUnit4.class)
public class RcatExceptionTest extends RcatBaseTest {
  @Test
  @SuppressWarnings("CheckReturnValue")
  public void invalidCiphertextProto_raisesDecryptionException() throws Throwable {
    /* Malformed ciphertext */
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseToken token =
        RandomizedCounterAbuseToken.newBuilder()
            .setCiphertext(ByteString.copyFromUtf8("not a proto"))
            .build();

    assertThrows(
        RcatDecryptionException.class,
        () -> verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void invalidEnvelope_raisesParsingException() throws Throwable {
    /* Valid ciphertext but invalid content (envelope) */
    byte[] ciphertext = this.encrypt("invalid envelope".getBytes(UTF_8));
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseToken token =
        RandomizedCounterAbuseToken.newBuilder()
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .build();

    assertThrows(
        RcatParsingException.class,
        () -> verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void unknownIssuerId_raisesUnknownIssuerIdException() throws Throwable {
    /* Issuer uses the wrong issuerId which does not have any matching keyset for the verifier. */
    int otherIssuerId = 987654321;
    RcatIssuer issuer =
        RcatIssuer.builder()
            .setMonthlySalt(this.monthlySalt)
            .setIssuerId(otherIssuerId)
            .setRcatCryptoSigner(
                RcatTinkCrypto.Signer.withPrivateKeysetHandle(this.issuerPrivateKeysetHandle))
            .setRcatCryptoEncrypter(
                RcatTinkCrypto.Encrypter.withPublicKeysetHandle(this.verifierPublicKeysetHandle))
            .setN(this.numberOfUsersToAssign)
            .setK(this.numberOfUsersPerGroup)
            .build();
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseToken token = issuer.generateToken(this.userId, this.contentId);

    assertThrows(
        RcatUnknownIssuerIdException.class,
        () -> verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void badIssuerPrivateKey_raisesSignatureValidationException() throws Throwable {
    /* Issuer uses different keyset than what is expected by the verifier. */
    KeysetHandle otherIssuerPrivateKeysetHandle =
        KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    RcatIssuer issuer =
        RcatIssuer.builder()
            .setMonthlySalt(this.monthlySalt)
            .setIssuerId(this.issuerId)
            .setRcatCryptoSigner(
                RcatTinkCrypto.Signer.withPrivateKeysetHandle(otherIssuerPrivateKeysetHandle))
            .setRcatCryptoEncrypter(
                RcatTinkCrypto.Encrypter.withPublicKeysetHandle(this.verifierPublicKeysetHandle))
            .setN(this.numberOfUsersToAssign)
            .setK(this.numberOfUsersPerGroup)
            .build();
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseToken token = issuer.generateToken(this.userId, this.contentId);

    assertThrows(
        RcatSignatureValidationException.class,
        () -> verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void invalidEnvelopePayload_raisesParsingException() throws Throwable {
    /* Valid envelope with invalid payload. */
    byte[] payload = "invalid payload".getBytes(UTF_8);
    byte[] signature = this.sign(payload);
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseTokenEnvelope envelope =
        RandomizedCounterAbuseTokenEnvelope.newBuilder()
            .setIssuerId(this.issuerId)
            .setPayload(ByteString.copyFrom(payload))
            .setSignature(ByteString.copyFrom(signature))
            .build();
    RandomizedCounterAbuseToken token =
        RandomizedCounterAbuseToken.newBuilder()
            .setCiphertext(ByteString.copyFrom(this.encrypt(envelope.toByteArray())))
            .build();

    assertThrows(
        RcatParsingException.class,
        () -> verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void invalidContentBinding_raisesInvalidContentBindingException() throws Throwable {
    /* Content ID is different from what the token is for. */
    RcatIssuer issuer =
        RcatIssuer.builder()
            .setMonthlySalt(this.monthlySalt)
            .setIssuerId(this.issuerId)
            .setRcatCryptoSigner(
                RcatTinkCrypto.Signer.withPrivateKeysetHandle(this.issuerPrivateKeysetHandle))
            .setRcatCryptoEncrypter(
                RcatTinkCrypto.Encrypter.withPublicKeysetHandle(this.verifierPublicKeysetHandle))
            .setN(this.numberOfUsersToAssign)
            .setK(this.numberOfUsersPerGroup)
            .build();
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseToken token = issuer.generateToken(this.userId, this.contentId);

    assertThrows(
        RcatInvalidContentBindingException.class,
        () -> verifier.validateToken(token, "Different content!", RcatUtils.EMPTY_NONCE));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void expiredToken_raisesRcatExpiredException() throws Throwable {
    /* Issuer sent an outdated token. */
    Instant instant = Instant.now().minus(Duration.ofHours(2));
    RcatIssuer issuer =
        RcatIssuer.builder()
            .setMonthlySalt(this.monthlySalt)
            .setIssuerId(this.issuerId)
            .setRcatCryptoSigner(
                RcatTinkCrypto.Signer.withPrivateKeysetHandle(this.issuerPrivateKeysetHandle))
            .setRcatCryptoEncrypter(
                RcatTinkCrypto.Encrypter.withPublicKeysetHandle(this.verifierPublicKeysetHandle))
            .setN(this.numberOfUsersToAssign)
            .setK(this.numberOfUsersPerGroup)
            .setInstant(instant)
            .build();
    RcatVerifier verifier =
        RcatVerifier.builder()
            .setPartnerRcatCryptoVerifierMapping(
                Collections.singletonMap(
                    this.issuerId,
                    RcatTinkCrypto.Verifier.withPublicKeysetHandle(this.issuerPublicKeysetHandle)))
            .setRcatCryptoDecrypter(
                RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(this.verifierPrivateKeysetHandle))
            .build();
    RandomizedCounterAbuseToken token = issuer.generateToken(this.userId, this.contentId);

    assertThrows(
        RcatExpiredException.class,
        () -> verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE));
  }

  /* Crypto methods */

  private byte[] sign(byte[] data) throws GeneralSecurityException {
    return this.sign(data, this.issuerPrivateKeysetHandle);
  }

  private byte[] sign(byte[] data, KeysetHandle privateKeysetHandle)
      throws GeneralSecurityException {
    PublicKeySign signer = privateKeysetHandle.getPrimitive(PublicKeySign.class);
    return signer.sign(data);
  }

  private byte[] encrypt(byte[] data) throws GeneralSecurityException {
    return this.encrypt(data, this.verifierPublicKeysetHandle);
  }

  private byte[] encrypt(byte[] data, KeysetHandle publicKeysetHandle)
      throws GeneralSecurityException {
    HybridEncrypt encrypter = publicKeysetHandle.getPrimitive(HybridEncrypt.class);
    return encrypter.encrypt(data, new byte[0]);
  }
}
