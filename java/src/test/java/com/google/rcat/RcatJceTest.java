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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.UnsignedInteger;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.devtools.build.runfiles.Runfiles;
import com.google.rcat.error.RcatSignatureValidationException;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests with JCE using Tink wire format for RCATs. */
@RunWith(JUnit4.class)
public final class RcatJceTest extends RcatBaseTest {

  private static final String ISSUER_PRIVATE_KEYSET_PATH =
      "rcat_java/src/test/java/com/google/rcat/issuer-private-keyset-jce-test-only.tink.json";
  private static final String ISSUER_PRIVATE_KEY_RAW =
      "AJccIlx5slNIBKaFOA+/g3iodzFpo31lEaUQuT/ffMnC";

  private UnsignedInteger issuerPublicKeyId;
  private PrivateKey issuerJcePrivateKey;

  @Before
  @Override
  public void setUp() throws Exception {
    super.setUp();

    this.issuerPublicKeyId = UnsignedInteger.valueOf(2094097183);
  }

  @Override
  protected void setUpKeyPairs() throws Exception {
    SignatureConfig.register();
    HybridConfig.register();

    Runfiles runfiles = Runfiles.create();
    String issuerPrivateKeysetPath = runfiles.rlocation(ISSUER_PRIVATE_KEYSET_PATH);
    this.issuerPrivateKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(issuerPrivateKeysetPath), UTF_8),
            InsecureSecretKeyAccess.get());
    this.issuerPublicKeysetHandle = this.issuerPrivateKeysetHandle.getPublicKeysetHandle();

    this.verifierPrivateKeysetHandle =
        KeysetHandle.generateNew(
            KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM"));
    this.verifierPublicKeysetHandle = this.verifierPrivateKeysetHandle.getPublicKeysetHandle();

    this.issuerJcePrivateKey =
        EllipticCurves.getEcPrivateKey(
            EllipticCurves.CurveType.NIST_P256,
            BaseEncoding.base64().decode(ISSUER_PRIVATE_KEY_RAW));
  }

  /**
   * Demonstration of the general non-blinded issuance scheme with public key signing using JCE and
   * Tink wire format.
   */
  @Test
  public void nonBlindedJceIssuerWithTinkWireFormat_ok() throws Exception {
    RcatIssuer issuer =
        RcatIssuer.builder()
            .setMonthlySalt(this.monthlySalt)
            .setIssuerId(this.issuerId)
            .setRcatCryptoSigner(
                RcatJceCrypto.Signer.builder()
                    .setPrivateKey(this.issuerJcePrivateKey)
                    .setPublicKeyId(this.issuerPublicKeyId)
                    .build())
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

    long groupId = verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE);

    this.assertGroupId(groupId);
  }

  /** Demonstration of an issuer using JCE without Tink wire format. */
  @Test
  public void nonBlindedJceIssuerWithoutTinkWireFormat_raisesSignatureValidationException()
      throws Exception {
    /** Issuer uses JCE without Tink wire format. */
    RcatIssuer issuer =
        RcatIssuer.builder()
            .setMonthlySalt(this.monthlySalt)
            .setIssuerId(this.issuerId)
            .setRcatCryptoSigner(
                RcatJceCrypto.Signer.builder()
                    .setPrivateKey(this.issuerJcePrivateKey)
                    .setUseTinkWireFormat(false)
                    .build())
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

  /**
   * Test ensures that the header of the signature match the Tink wire format, 0x01 for the version,
   * ED9971D9 for the public key id: 3,986,256,345.
   */
  @Test
  public void getTinkHeaderUnsignedInteger_ok() throws Exception {
    UnsignedInteger publicKeyId = UnsignedInteger.valueOf("3986256345");
    RcatJceCrypto.Signer signer =
        RcatJceCrypto.Signer.builder()
            .setPrivateKey(this.issuerJcePrivateKey)
            .setPublicKeyId(publicKeyId)
            .build();

    byte[] tinkHeader = signer.getTinkHeader();

    assertThat(tinkHeader).isEqualTo(BaseEncoding.base16().decode("01ED9971D9"));
    assertThat(
            new BigInteger(
                    1,
                    ByteBuffer.allocate(4)
                        .order(ByteOrder.BIG_ENDIAN)
                        .put(tinkHeader, 1, 4)
                        .array())
                .longValue())
        .isEqualTo(publicKeyId.longValue());
  }
}
