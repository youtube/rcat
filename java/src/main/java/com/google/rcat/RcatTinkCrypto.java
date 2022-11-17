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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.rcat.error.RcatDecryptionException;
import com.google.rcat.error.RcatEncryptionException;
import com.google.rcat.error.RcatSignatureValidationException;
import com.google.rcat.error.RcatSigningException;
import java.security.GeneralSecurityException;

/** Static Tink implementations for RCATs cryptographic operations. */
@CheckReturnValue
public final class RcatTinkCrypto {

  /** A {@code Signer} that performs public key signing operation with Tink. */
  public static class Signer implements RcatCrypto.Signer {

    private final KeysetHandle privateKeysetHandle;

    /**
     * Computes the signature for {@code data}.
     *
     * @return the signature of {@code data}.
     * @throws RcatSigningException if unable to sign the {@code data}.
     */
    @Override
    public byte[] sign(byte[] data) throws RcatSigningException {
      try {
        PublicKeySign signer = this.privateKeysetHandle.getPrimitive(PublicKeySign.class);
        return signer.sign(data);
      } catch (GeneralSecurityException e) {
        throw new RcatSigningException("Unable to create signature for payload bytes.", e);
      }
    }

    /**
     * Creates a new instance of {@code RcatTinkCrypto.Signer} with a specified private Tink {@code
     * KeysetHandle}.
     *
     * @param privateKeysetHandle Private Tink keyset handle to issue signature of {@code data}.
     */
    public static RcatTinkCrypto.Signer withPrivateKeysetHandle(KeysetHandle privateKeysetHandle) {
      return new RcatTinkCrypto.Signer(privateKeysetHandle);
    }

    private Signer(KeysetHandle privateKeysetHandle) {
      this.privateKeysetHandle = privateKeysetHandle;
    }
  }

  /** A {@code Verifier} that performs public key signing verification operation with Tink. */
  public static class Verifier implements RcatCrypto.Verifier {

    private final KeysetHandle publicKeysetHandle;

    /**
     * Verifies whether {@code signature} is a valid signature for {@code data}.
     *
     * @throws RcatSignatureValidationException if {@code signature} is not a valid signature for
     *     {@code data}.
     */
    @Override
    public void verify(byte[] signature, byte[] data) throws RcatSignatureValidationException {
      try {
        PublicKeyVerify verifier = this.publicKeysetHandle.getPrimitive(PublicKeyVerify.class);
        verifier.verify(signature, data);
      } catch (GeneralSecurityException e) {
        throw new RcatSignatureValidationException(
            "Unable to verify signature of RCAT payload.", e);
      }
    }

    /**
     * Creates a new instance of {@code RcatTinkCrypto.Verifier} with a specified public Tink {@code
     * KeysetHandle}.
     *
     * @param publicKeysetHandle Public Tink keyset handle to verify signature for a given {@code
     *     data}.
     */
    public static RcatTinkCrypto.Verifier withPublicKeysetHandle(KeysetHandle publicKeysetHandle) {
      return new RcatTinkCrypto.Verifier(publicKeysetHandle);
    }

    private Verifier(KeysetHandle publicKeysetHandle) {
      this.publicKeysetHandle = publicKeysetHandle;
    }
  }

  /** An {@code Encrypter} that performs encryption operation with Tink. */
  public static class Encrypter implements RcatCrypto.Encrypter {

    private final KeysetHandle publicKeysetHandle;

    /**
     * Encrypts {@code plaintext} binding {@code contextInfo} to the resulting ciphertext.
     *
     * @return resulting ciphertext.
     * @throws RcatEncryptionException if unable to generate a ciphertext.
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo) throws RcatEncryptionException {
      try {
        HybridEncrypt encrypter = this.publicKeysetHandle.getPrimitive(HybridEncrypt.class);
        return encrypter.encrypt(plaintext, contextInfo);
      } catch (GeneralSecurityException e) {
        throw new RcatEncryptionException("Unable to encrypt RCAT token envelope.", e);
      }
    }

    /**
     * Creates a new instance of {@code RcatTinkCrypto.Encrypter} with a specified public Tink
     * {@code KeysetHandle}.
     *
     * @param publicKeysetHandle Public Tink keyset handle to encrypt the {@code data} with.
     */
    public static RcatTinkCrypto.Encrypter withPublicKeysetHandle(KeysetHandle publicKeysetHandle) {
      return new RcatTinkCrypto.Encrypter(publicKeysetHandle);
    }

    private Encrypter(KeysetHandle publicKeysetHandle) {
      this.publicKeysetHandle = publicKeysetHandle;
    }
  }

  /** An {@code Decrypter} that performs decryption operation with Tink. */
  public static class Decrypter implements RcatCrypto.Decrypter {

    private final KeysetHandle privateKeysetHandle;

    /**
     * Decrypts {@code ciphertext} verifying the integrity of {@code contextInfo}.
     *
     * @return resulting plaintext.
     * @throws RcatDecryptionException if the ciphertext can not be decrypted.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] contextInfo) throws RcatDecryptionException {
      try {
        HybridDecrypt decrypter = this.privateKeysetHandle.getPrimitive(HybridDecrypt.class);
        return decrypter.decrypt(ciphertext, contextInfo);
      } catch (GeneralSecurityException e) {
        throw new RcatDecryptionException("Unable to decrypt RCAT token envelope.", e);
      }
    }

    /**
     * Creates a new instance of {@code RcatTinkCrypto.Decrypter} with a specified private Tink
     * {@code KeysetHandle}.
     *
     * @param privateKeysetHandle Private Tink keyset handle to decrypt the {@code data}.
     */
    public static RcatTinkCrypto.Decrypter withPrivateKeysetHandle(
        KeysetHandle privateKeysetHandle) {
      return new RcatTinkCrypto.Decrypter(privateKeysetHandle);
    }

    private Decrypter(KeysetHandle privateKeysetHandle) {
      this.privateKeysetHandle = privateKeysetHandle;
    }
  }

  private RcatTinkCrypto() {}
}
