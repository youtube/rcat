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

import com.google.rcat.proto.RandomizedCounterAbuseToken;
import java.time.Instant;
import java.util.Collections;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests blinded and non-blinded issuance of RCATs.
 *
 * <p>These tests demonstrate how a token may be issued and validated, both in the general as well
 * as the blinded e2ee case.
 */
@RunWith(JUnit4.class)
public class RcatTest extends RcatBaseTest {
  @Test
  public void nonBlindedIssuer_ok() throws Throwable {
    /* Demonstration of the general non-blinded issuance scheme. */
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

    Instant start = Instant.now();
    // First-party client calls the issuer which uses the authenticated identity and content of
    // relevance to generate a RCAT.
    for (int i = 0; i < 1000; i++) {
      RandomizedCounterAbuseToken token = issuer.generateToken(this.userId, this.contentId);

      long groupId = verifier.validateToken(token, this.contentId, RcatUtils.EMPTY_NONCE);

      this.assertGroupId(groupId);
    }
    System.out.println("Time taken:");
    System.out.println(Instant.now() - start);
  }

  @Test
  public void blindedIssuer_ok() throws Throwable {
    /* Demonstration of a blinded issuance scheme. */
    byte[] nonce = this.generateNonce();
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

    // First-party client generates content binding using its local nonce.
    long contentBinding = RcatUtils.computeContentBinding(this.contentId, nonce);

    // First-party client calls the issuer which uses the authenticated identity and client-side
    // computed content binding to generate a RCAT.
    RandomizedCounterAbuseToken token = issuer.generateTokenE2ee(this.userId, contentBinding);

    // The verifier knowns the content being accessed, and uses this to validate the token.
    long groupId = verifier.validateToken(token, this.contentId, nonce);

    this.assertGroupId(groupId);
  }
}
