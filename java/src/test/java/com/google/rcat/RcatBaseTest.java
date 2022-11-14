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

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.SecureRandom;
import java.util.Random;
import org.junit.Before;

/** Base class for RCAT tests. */
public class RcatBaseTest {

  private static final int MONTHLY_SALT_BYTE_LENGTH = 32;

  private static final int CONTENT_BINDING_NONCE_BYTE_LENGTH = 32;

  protected int numberOfUsersToAssign;
  protected int numberOfUsersPerGroup;
  protected byte[] monthlySalt;
  protected int issuerId;
  protected String contentId;
  protected byte[] userId;
  protected KeysetHandle issuerPrivateKeysetHandle;
  protected KeysetHandle issuerPublicKeysetHandle;
  protected KeysetHandle verifierPrivateKeysetHandle;
  protected KeysetHandle verifierPublicKeysetHandle;

  @Before
  public void setUp() throws Exception {
    this.numberOfUsersToAssign = 1000000;
    this.numberOfUsersPerGroup = 100;
    this.monthlySalt = this.generateMonthlySalt();
    this.issuerId = 151;
    // For YouTube, the content ID will be a YouTube video ID.
    this.contentId = "dQw4w9WgXcQ";
    this.userId = "user@foo.com".getBytes(UTF_8);

    this.setUpKeyPairs();
  }

  protected void setUpKeyPairs() throws Exception {
    SignatureConfig.register();
    HybridConfig.register();

    this.issuerPrivateKeysetHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    this.issuerPublicKeysetHandle = this.issuerPrivateKeysetHandle.getPublicKeysetHandle();

    this.verifierPrivateKeysetHandle =
        KeysetHandle.generateNew(
            KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM"));
    this.verifierPublicKeysetHandle = this.verifierPrivateKeysetHandle.getPublicKeysetHandle();
  }

  /**
   * Generates a random {@code MONTHLY_SALT_BYTE_LENGTH} bytes array.
   *
   * <p>As the name suggest, the salt should be updated on a regular basis and should prevent
   * malicious third party from predicting the group id of a given user. Please refer to the RCAT
   * explainer for more details.
   *
   * @return an array of bytes representing a monthly salt.
   */
  protected byte[] generateMonthlySalt() {
    Random rand = new SecureRandom();
    byte[] monthlySalt = new byte[MONTHLY_SALT_BYTE_LENGTH];
    rand.nextBytes(monthlySalt);
    return monthlySalt;
  }

  /**
   * Generates a random {@code CONTENT_BINDING_NONCE_BYTE_LENGTH} bytes array.
   *
   * <p>The nonce is used for content binding which prevents the token from being stolen and reused
   * outside the content_id for which it was intended.
   *
   * @return an array of bytes representing the nonce.
   */
  protected byte[] generateNonce() {
    Random rand = new SecureRandom();
    byte[] nonce = new byte[CONTENT_BINDING_NONCE_BYTE_LENGTH];
    rand.nextBytes(nonce);
    return nonce;
  }

  /**
   * Asserts that a group id is valid.
   *
   * <p>A group id should be considered as valid if it is greater than 0 and less than the number of
   * groups defined by the number of users and number of users per group.
   */
  protected void assertGroupId(long groupId) {
    assertThat(groupId).isGreaterThan(0);
    assertThat(groupId).isLessThan(this.numberOfUsersToAssign / this.numberOfUsersPerGroup);
  }
}
