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

package com.google.rcat.helpers;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.primitives.UnsignedInteger;
import com.google.common.primitives.UnsignedLong;
import com.google.protobuf.ByteString;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import com.google.rcat.proto.RandomizedCounterAbuseTokenEnvelope;
import com.google.rcat.proto.RandomizedCounterAbuseTokenPayload;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RcatProtobufWireFormatHelperTest {

  @Test
  public void encodeRcatPayloadAsBytes_ok() throws Exception {
    UnsignedLong groupId = UnsignedLong.valueOf(123456789123456789L);
    UnsignedLong contentBinding = UnsignedLong.valueOf(123456);
    UnsignedLong expirationUtcSec = UnsignedLong.valueOf(123);
    RandomizedCounterAbuseTokenPayload payload =
        RandomizedCounterAbuseTokenPayload.newBuilder()
            .setGroupId(groupId.longValue())
            .setContentBinding(contentBinding.longValue())
            .setExpirationUtcSec(expirationUtcSec.longValue())
            .build();
    byte[] expected = payload.toByteArray();

    assertThat(
            RcatProtobufWireFormatHelper.encodeRcatPayloadAsBytes(
                groupId, contentBinding, expirationUtcSec))
        .isEqualTo(expected);
  }

  @Test
  public void encodeRcatEnvelopeAsBytes_ok() throws Exception {
    UnsignedInteger issuerId = UnsignedInteger.valueOf(2997368055L);
    RandomizedCounterAbuseTokenEnvelope envelope =
        RandomizedCounterAbuseTokenEnvelope.newBuilder()
            .setIssuerId(issuerId.intValue())
            .setSignature(ByteString.copyFromUtf8("signature"))
            .setPayload(ByteString.copyFromUtf8("payload"))
            .build();
    byte[] expected = envelope.toByteArray();

    assertThat(
            RcatProtobufWireFormatHelper.encodeRcatEnvelopeAsBytes(
                issuerId, "signature".getBytes(UTF_8), "payload".getBytes(UTF_8)))
        .isEqualTo(expected);
  }

  @Test
  public void encodeRcatAsBytes_ok() throws Exception {
    RandomizedCounterAbuseToken token =
        RandomizedCounterAbuseToken.newBuilder()
            .setCiphertext(ByteString.copyFromUtf8("ciphertext"))
            .build();
    byte[] expected = token.toByteArray();

    assertThat(RcatProtobufWireFormatHelper.encodeRcatAsBytes("ciphertext".getBytes(UTF_8)))
        .isEqualTo(expected);
  }
}
