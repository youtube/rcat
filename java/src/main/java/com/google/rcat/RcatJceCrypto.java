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

import com.google.auto.value.AutoValue;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.primitives.UnsignedInteger;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.rcat.error.RcatSigningException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Optional;

/**
 * Class containing JCE implementation of RcatCrypto interfaces for RCATs.
 *
 * <p>This class is meant as an example and we strongly recommend using Tink cryptographic library,
 * https://developers.google.com/tink, if you can. This would help reduce potential security risks,
 * e.g. CVE-2022-21449, which currently affects various versions of OpenJDK.
 */
@CheckReturnValue
public final class RcatJceCrypto {

  /** Public key signing with JCE compatible with Tink wire format. */
  @AutoValue
  public abstract static class Signer implements RcatCrypto.Signer {

    private static final boolean DEFAULT_USE_TINK_WIRE_FORMAT = true;
    private static final int TINK_HEADER_BYTE_SIZE = 5;
    private static final byte TINK_VERSION = 1;

    abstract PrivateKey privateKey();

    abstract boolean useTinkWireFormat();

    abstract UnsignedInteger publicKeyId();

    @Override
    public byte[] sign(byte[] data) throws RcatSigningException {
      try {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(this.privateKey());
        signer.update(data);
        byte[] rawSignature = signer.sign();

        if (this.useTinkWireFormat()) {
          byte[] header = this.getTinkHeader();
          return ByteBuffer.allocate(header.length + rawSignature.length)
              .put(header)
              .put(rawSignature)
              .array();
        }

        return rawSignature;
      } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
        throw new RcatSigningException("Unable to create signature for payload bytes.", e);
      }
    }

    /**
     * Returns the signature header needed to be compatible with Tink.
     *
     * <p>Learn more about Tink Wire format: <a
     * href="https://developers.google.com/tink/wire-format">link</a>
     */
    @VisibleForTesting
    public byte[] getTinkHeader() {
      return ByteBuffer.allocate(TINK_HEADER_BYTE_SIZE)
          .order(ByteOrder.BIG_ENDIAN)
          .put(TINK_VERSION)
          .putInt(this.publicKeyId().intValue())
          .array();
    }

    public static Builder builder() {
      return new AutoValue_RcatJceCrypto_Signer.Builder()
          .setUseTinkWireFormat(DEFAULT_USE_TINK_WIRE_FORMAT);
    }

    /** Builder for RcatJceCrypto.Signer class. */
    @AutoValue.Builder
    public abstract static class Builder {
      public abstract Builder setPrivateKey(PrivateKey privateKey);

      public abstract Builder setUseTinkWireFormat(boolean useTinkWireFormat);

      public abstract Builder setPublicKeyId(UnsignedInteger publicKeyId);

      abstract boolean useTinkWireFormat();

      abstract Optional<UnsignedInteger> publicKeyId();

      abstract Signer autoBuild();

      @SuppressWarnings("CheckReturnValue")
      public final Signer build() {
        if (useTinkWireFormat()) {
          Preconditions.checkArgument(publicKeyId().isPresent(), "missing publicKeyId");
        } else {
          setPublicKeyId(UnsignedInteger.ZERO);
        }
        return autoBuild();
      }
    }
  }

  private RcatJceCrypto() {}
}
