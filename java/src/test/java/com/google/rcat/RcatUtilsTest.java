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
import static org.junit.Assert.assertThrows;

import com.google.common.io.BaseEncoding;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RcatUtilsTest {

  // For YouTube, the content ID will be a YouTube video ID.
  private static final String CONTENT_ID = "dQw4w9WgXcQ";

  private static final String NONCE_INVALID_BYTE_LENGTH_EXCEPTION_MSG = "nonce must be 32 bytes.";

  @Test
  public void computeContentBindingWithZeroNonce_ok() {
    // Refer to the RCAT explainer to understand how the content binding is being calculated.
    long expectedContentBindingId = Long.parseUnsignedLong("7717541790133102389");

    long contentBindingId = RcatUtils.computeContentBinding(CONTENT_ID, RcatUtils.EMPTY_NONCE);

    assertThat(contentBindingId).isEqualTo(expectedContentBindingId);
  }

  @Test
  public void computeContentBindingWith32BytesNonce_ok() {
    byte[] nonce =
        BaseEncoding.base16()
            .decode("AB41011BC4BFCC4360DD9EEEF86B041BAEDE087F5240856FD1B7601AEDC60E8D");
    long expectedContentBindingId = Long.parseUnsignedLong("4251249193307959102");

    long contentBindingId = RcatUtils.computeContentBinding(CONTENT_ID, nonce);

    assertThat(contentBindingId).isEqualTo(expectedContentBindingId);
  }

  @Test
  public void computeContentBindingWith1Byte_raisesIllegalArgumentException() {
    byte[] nonce = BaseEncoding.base16().decode("01");

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> RcatUtils.computeContentBinding(CONTENT_ID, nonce));

    assertThat(exception).hasMessageThat().isEqualTo(NONCE_INVALID_BYTE_LENGTH_EXCEPTION_MSG);
  }

  @Test
  public void computeContentBindingWith33BytesNonce_raisesIllegalArgumentException() {
    byte[] nonce =
        BaseEncoding.base16()
            .decode("010203040506070809101112131415161718192021222324252627282930313233");

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> RcatUtils.computeContentBinding(CONTENT_ID, nonce));

    assertThat(exception).hasMessageThat().isEqualTo(NONCE_INVALID_BYTE_LENGTH_EXCEPTION_MSG);
  }
}
