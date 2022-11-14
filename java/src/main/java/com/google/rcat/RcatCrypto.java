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

import com.google.errorprone.annotations.CheckReturnValue;
import com.google.rcat.error.RcatDecryptionException;
import com.google.rcat.error.RcatEncryptionException;
import com.google.rcat.error.RcatSignatureValidationException;
import com.google.rcat.error.RcatSigningException;

/** Static interfaces for RCATs cryptographic operations. */
@CheckReturnValue
public final class RcatCrypto {
  /** Interface for public key signing. */
  public interface Signer {
    /**
     * Computes the signature for {@code data}.
     *
     * @return the signature of {@code data}.
     * @throws RcatSigningException if unable to sign the {@code data}.
     */
    public byte[] sign(byte[] data) throws RcatSigningException;
  }

  /** Interface for public key signing. */
  public interface Verifier {
    /**
     * Verifies whether {@code signature} is a valid signature for {@code data}.
     *
     * @throws RcatSignatureValidationException if {@code signature} can not be verified for {@code
     *     data}.
     */
    public void verify(byte[] signature, byte[] data) throws RcatSignatureValidationException;
  }

  /** Interface for data encryption. */
  public interface Encrypter {
    /**
     * Encrypts {@code plaintext} binding {@code contextInfo} to the resulting ciphertext.
     *
     * <p>{@code contextInfo} is usually public data implicit from the context, but which should be
     * bound to the resulting {@code ciphertext}. The latter can then be used to confirm the
     * integrity of the {@code contextInfo} in the decryption process.
     *
     * @return resulting ciphertext.
     * @throws RcatEncryptionException if unable to generate a ciphertext.
     */
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo) throws RcatEncryptionException;
  }

  /** Interface for data decryption. */
  public interface Decrypter {
    /**
     * Decrypts {@code ciphertext} verifying the integrity of {@code contextInfo}.
     *
     * @return resulting plaintext.
     * @throws RcatDecryptionException if the ciphertext can not be decrypted.
     */
    public byte[] decrypt(byte[] ciphertext, byte[] contextInfo) throws RcatDecryptionException;
  }

  private RcatCrypto() {}
}
