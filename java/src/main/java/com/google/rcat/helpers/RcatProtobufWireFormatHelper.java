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

import com.google.common.primitives.UnsignedInteger;
import com.google.common.primitives.UnsignedLong;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Helper methods to serialize RCATs using Protobuf wire format.
 *
 * <p>This class is provided only as a point of reference. We strongly encourage using the official
 * Protobuffer library as the wire format might be subject to change over time.
 *
 * <p>Protobuffer encoding details:
 * https://developers.google.com/protocol-buffers/docs/encoding#simple
 *
 * <p>This is a simplified version of the official CodedOutputStream class
 * https://github.com/protocolbuffers/protobuf/blob/main/java/core/src/main/java/com/google/protobuf/CodedOutputStream.java
 */
final class RcatProtobufWireFormatHelper {

  private enum WireFormat {
    WIRETYPE_VARINT((byte) 0),
    WIRETYPE_LENGTH_DELIMITED((byte) 2);

    private final byte value;

    public byte getValue() {
      return value;
    }

    private WireFormat(byte value) {
      this.value = value;
    }
  };

  /** Generates bytes array representing RandomizedCounterAbuseTokenPayload proto message. */
  public static byte[] encodeRcatPayloadAsBytes(
      UnsignedLong groupId, UnsignedLong contentBinding, UnsignedLong expirationUtcSec)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Write group id
    writeTag(out, (byte) 1, WireFormat.WIRETYPE_VARINT);
    writeUInt64(out, groupId.longValue());
    // Write content binding
    writeTag(out, (byte) 2, WireFormat.WIRETYPE_VARINT);
    writeUInt64(out, contentBinding.longValue());
    // Write expiration utc sec
    writeTag(out, (byte) 3, WireFormat.WIRETYPE_VARINT);
    writeUInt64(out, expirationUtcSec.longValue());
    return out.toByteArray();
  }

  /** Generates bytes array representing RandomizedCounterAbuseTokenEnvelope proto message. */
  public static byte[] encodeRcatEnvelopeAsBytes(
      UnsignedInteger issuerId, byte[] signature, byte[] payload) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Write issuer id
    writeTag(out, (byte) 1, WireFormat.WIRETYPE_VARINT);
    writeUInt32(out, issuerId.intValue());
    // Write signature
    writeTag(out, (byte) 2, WireFormat.WIRETYPE_LENGTH_DELIMITED);
    writeBytes(out, signature);
    // Write payload
    writeTag(out, (byte) 3, WireFormat.WIRETYPE_LENGTH_DELIMITED);
    writeBytes(out, payload);
    return out.toByteArray();
  }

  /** Generates bytes array representing RandomizedCounterAbuseToken proto message. */
  public static byte[] encodeRcatAsBytes(byte[] ciphertext) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Write ciphertext
    writeTag(out, (byte) 1, WireFormat.WIRETYPE_LENGTH_DELIMITED);
    writeBytes(out, ciphertext);
    return out.toByteArray();
  }

  /** Encodes and writes a tag. */
  private static void writeTag(OutputStream out, byte fieldNumber, WireFormat wireFormat)
      throws IOException {
    out.write(fieldNumber << 3 | wireFormat.getValue());
  }

  /** Write a {@code uint32} field, including tag, to the stream. */
  private static void writeUInt32(OutputStream out, int value) throws IOException {
    while (true) {
      if ((value & ~0x7F) == 0) {
        out.write((byte) value);
        return;
      } else {
        out.write((byte) (value & 0x7F) | 0x80);
        value >>>= 7;
      }
    }
  }

  /** Write a {@code uint64} field, including tag, to the stream. */
  private static void writeUInt64(OutputStream out, long value) throws IOException {
    while (true) {
      if ((value & ~0x7FL) == 0) {
        out.write((byte) value);
        return;
      } else {
        out.write((byte) ((int) value & 0x7F) | 0x80);
        value >>>= 7;
      }
    }
  }

  /** Write a {@code bytes} field, including tag, to the stream. */
  private static void writeBytes(OutputStream out, byte[] data) throws IOException {
    writeUInt32(out, data.length);
    out.write(data);
  }

  private RcatProtobufWireFormatHelper() {}
}
