/*
 * Copyright 2026 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridConfig2026;
import com.google.crypto.tink.hybrid.PredefinedHybridParameters;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureConfig2026;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KeysetHandleConverterTest {

  @Rule public final TemporaryFolder tempFolder = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    SignatureConfig.register();
    HybridConfig.register();
  }

  @Test
  public void convert_ecdsaKeysets_returnsMatchingKeysetHandles() throws Exception {
    KeysetHandle privateKeysetHandle =
        KeysetHandle.generateNew(
            PredefinedSignatureParameters.ECDSA_P256, SignatureConfig2026.get());
    KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

    File privateKeysetFile = tempFolder.newFile("issuer-private-keyset.tink.json");
    Files.writeString(
        privateKeysetFile.toPath(),
        TinkJsonProtoKeysetFormat.serializeKeyset(
            privateKeysetHandle, SignatureConfig2026.get(), InsecureSecretKeyAccess.get()));

    File publicKeysetFile = tempFolder.newFile("issuer-public-keyset.tink.json");
    Files.writeString(
        publicKeysetFile.toPath(),
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
            publicKeysetHandle, SignatureConfig2026.get()));

    KeysetHandleConverter converter = new KeysetHandleConverter();
    KeysetHandle convertedPrivate = converter.convert(privateKeysetFile.getPath());
    KeysetHandle convertedPublic = converter.convert(publicKeysetFile.getPath());

    assertThat(convertedPrivate.equalsKeyset(privateKeysetHandle)).isTrue();
    assertThat(convertedPublic.equalsKeyset(publicKeysetHandle)).isTrue();

    byte[] data = "rcat-payload".getBytes(UTF_8);
    byte[] signature =
        convertedPrivate.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class).sign(data);
    convertedPublic
        .getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class)
        .verify(signature, data);
  }

  @Test
  public void convert_hpkeKeysets_returnsMatchingKeysetHandles() throws Exception {
    KeysetHandle privateKeysetHandle =
        KeysetHandle.generateNew(
            PredefinedHybridParameters.HPKE_X25519_HKDF_SHA256_AES_128_GCM, HybridConfig2026.get());
    KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

    File privateKeysetFile = tempFolder.newFile("verifier-private-keyset.tink.json");
    Files.writeString(
        privateKeysetFile.toPath(),
        TinkJsonProtoKeysetFormat.serializeKeyset(
            privateKeysetHandle, HybridConfig2026.get(), InsecureSecretKeyAccess.get()));

    File publicKeysetFile = tempFolder.newFile("verifier-public-keyset.tink.json");
    Files.writeString(
        publicKeysetFile.toPath(),
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
            publicKeysetHandle, HybridConfig2026.get()));

    KeysetHandleConverter converter = new KeysetHandleConverter();
    KeysetHandle convertedPrivate = converter.convert(privateKeysetFile.getPath());
    KeysetHandle convertedPublic = converter.convert(publicKeysetFile.getPath());

    assertThat(convertedPrivate.equalsKeyset(privateKeysetHandle)).isTrue();
    assertThat(convertedPublic.equalsKeyset(publicKeysetHandle)).isTrue();

    byte[] plaintext = "rcat-envelope".getBytes(UTF_8);
    byte[] contextInfo = "rcat-context".getBytes(UTF_8);
    byte[] ciphertext =
        convertedPublic
            .getPrimitive(HybridConfig2026.get(), HybridEncrypt.class)
            .encrypt(plaintext, contextInfo);
    byte[] decrypted =
        convertedPrivate
            .getPrimitive(HybridConfig2026.get(), HybridDecrypt.class)
            .decrypt(ciphertext, contextInfo);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void convert_invalidKeysetJson_throwsGeneralSecurityException() throws Exception {
    File invalidKeysetFile = tempFolder.newFile("invalid-keyset.tink.json");
    Files.writeString(invalidKeysetFile.toPath(), "not valid json");

    KeysetHandleConverter converter = new KeysetHandleConverter();

    assertThrows(
        GeneralSecurityException.class, () -> converter.convert(invalidKeysetFile.getPath()));
  }

  @Test
  public void convert_missingFile_throwsIOException() {
    File missingFile = new File(tempFolder.getRoot(), "missing-keyset.tink.json");
    KeysetHandleConverter converter = new KeysetHandleConverter();

    assertThrows(IOException.class, () -> converter.convert(missingFile.getPath()));
  }
}
