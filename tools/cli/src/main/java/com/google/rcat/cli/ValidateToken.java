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

package com.google.rcat.cli;

import com.google.common.flogger.FluentLogger;
import com.google.common.primitives.UnsignedInteger;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.rcat.RcatTinkCrypto;
import com.google.rcat.RcatVerifier;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

/**
 * This command validates that a Randomized Counter-Abuse Token is valid for a given content
 * binding.
 *
 * <pre>{@code
 * bazel run :cli -- validate-token
 *   --verifier-private-keyset=<...>
 *   --issuer-public-keyset=<...>
 *   --issuer-id=<...>
 *   --token=<...>
 *   --content-id=<...>
 * }</pre>
 */
@Command(name = "validate-token", description = "Validates Randomized Counter-Abuse Token.")
final class ValidateToken implements Callable<Integer> {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @Spec CommandSpec spec;

  @Option(
      names = "--verifier-private-keyset",
      required = true,
      description = "Path to the verifier private keyset in TINK JSON format used for decryption.")
  private KeysetHandle verifierPrivateKeysetHandle;

  @Option(
      names = "--issuer-public-keyset",
      required = true,
      description =
          "Path to the issuer public keyset in TINK JSON format used for signature validation.")
  private KeysetHandle issuerPublicKeysetHandle;

  @Option(
      names = "--issuer-id",
      required = true,
      description =
          "4-bytes unsigned integer communicated out-of-band to identify the token issuer.")
  private UnsignedInteger issuerId;

  @Option(
      names = {"-t", "--token"},
      required = true,
      description = "Randomized Counter-Abuse Token encoded using Base64 URL-safe.",
      converter = RandomizedCounterAbuseTokenConverter.class)
  private RandomizedCounterAbuseToken token;

  @Option(
      names = "--content-id",
      required = true,
      description = "Content for which the Randomized Counter-Abuse Token has been issued.")
  private String contentId;

  private byte[] nonce;

  @Option(
      names = "--nonce",
      required = false,
      defaultValue = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      description = "32-bytes nonce encoded using Base64 URL-safe.")
  public void setNonce(ByteBuffer value) {
    if (value.hasRemaining()) {
      nonce = new byte[value.remaining()];
      value.get(nonce);
    }

    if (nonce == null || nonce.length != 32) {
      throw new ParameterException(
          spec.commandLine(),
          "Invalid value for option '--nonce': value must be exactly 32 bytes.");
    }
  }

  @Override
  public Integer call() {
    try {
      HybridConfig.register();
      SignatureConfig.register();

      RcatVerifier verifier =
          RcatVerifier.builder()
              .setPartnerRcatCryptoVerifierMapping(
                  Collections.singletonMap(
                      issuerId.intValue(),
                      RcatTinkCrypto.Verifier.withPublicKeysetHandle(issuerPublicKeysetHandle)))
              .setRcatCryptoDecrypter(
                  RcatTinkCrypto.Decrypter.withPrivateKeysetHandle(verifierPrivateKeysetHandle))
              .build();
      long groupId = verifier.validateToken(token, contentId, nonce);

      System.out.printf("Group Identifier: %s%n", groupId);
    } catch (Exception e) {
      logger.atSevere().withCause(e).log();
    }
    return 0;
  }

  private ValidateToken() {}
}
