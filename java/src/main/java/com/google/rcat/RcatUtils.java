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

import com.google.common.hash.Hashing;
import com.google.errorprone.annotations.CheckReturnValue;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Utility class for reference implementation of RCATs. */
@CheckReturnValue
public final class RcatUtils {

  private static final int CONTENT_BINDING_NONCE_BYTE_LENGTH = 32;

  // An array of 32 zero bytes.
  //
  // The array should only be used as key of the Hashing function. The latter does not mutate the
  // key used therefore it is safe to expose this as a public static field. We care about
  // performance and we want to avoid copying this EMPTY_NONCE everytime it is used.
  @SuppressWarnings("MutablePublicArray")
  public static final byte[] EMPTY_NONCE = new byte[CONTENT_BINDING_NONCE_BYTE_LENGTH];

  /**
   * Computes a content binding value.
   *
   * <p>Blinded applications invoke this on the client with a random nonce, non-blinded applications
   * set the nonce to zero.
   *
   * @param contentId a UTF-8 string containing the ID of content being bound. This must be the same
   *     ID (e.g. 11-character video ID) for 1P and 3P.
   * @param nonce a 32 bytes array to be shared between 1P and 3P for content binding. Set to {@code
   *     RcatUtils.EMPTY_NONCE} for non-blinded applications.
   * @return a 64-bit long content binding integer value.
   */
  public static long computeContentBinding(String contentId, byte[] nonce) {
    if (nonce.length != CONTENT_BINDING_NONCE_BYTE_LENGTH) {
      throw new IllegalArgumentException(
          "nonce must be " + CONTENT_BINDING_NONCE_BYTE_LENGTH + " bytes.");
    }

    // The content binding hash is keyed with the bytes of the client nonce
    // and computes a digest of the content ID UTF-8 byte values
    byte[] message = contentId.getBytes(UTF_8);
    // using sha256. The digest bytes
    byte[] digest = Hashing.hmacSha256(nonce).hashBytes(message).asBytes();
    // in little endian order are then truncated to 8 bytes (long) in big-endian order.
    return ByteBuffer.wrap(digest)
        .order(ByteOrder.LITTLE_ENDIAN)
        .getLong(); // _CONTENT_BINDING_LENGTH_BYTES = 8
  }

  private RcatUtils() {}
}
