# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Python implementation of the RCATs API.

RCATs are randomized counter abuse tokens, which allow a first party to
associate a many-user group with content interactions for the purpose of fraud
detection.

This script implements the functionality described in the RCATs explainer
(README.md) for token issuers and verifiers. Please refer to rcat_test for
end-to-end examples of both the non-blinded and e2ee use cases. RCATs are
are 272 bytes, and blinded content binding requires an additional 32 byte nonce
to be relayed, resulting in a total of 304 bytes per RCAT + nonce.
"""
import datetime
import hashlib
import hmac

import tink
from tink import core
from tink import hybrid
from tink import signature

from google.protobuf import message
from rcat.proto import rcat_pb2

# Initializing the primitives at time of import.
signature.register()
hybrid.register()

_CONTENT_BINDING_NONCE_LENGTH_BYTES = 32

_CONTENT_BINDING_LENGTH_BYTES = 8

# Creates an array of 32 zero bytes
EMPTY_NONCE = bytearray(_CONTENT_BINDING_NONCE_LENGTH_BYTES)


class ServerError(Exception):
  """Abstract parent class for all RCAT exceptions."""


class IssuanceError(ServerError):
  """Abstract parent class for all RCAT issuance exceptions."""


class IssuanceInitializationError(Exception):
  """Initialization of the issuer failed."""


class EncryptionError(IssuanceError):
  """Encryption of the RCAT failed."""


class SigningError(IssuanceError):
  """Signing of the RCAT failed."""


class VerificationError(ServerError):
  """Abstract parent class for all RCAT verification exceptions."""


class SignatureValidationError(VerificationError):
  """RCAT Signature could not be validated."""


class DecryptionError(VerificationError):
  """RCAT Decryption failed."""


class UnknownIssuerIdError(VerificationError):
  """RCAT fetching issuer failed."""


class ParsingError(VerificationError):
  """RCAT parsing failed."""


class ContentBindingError(VerificationError):
  """RCAT Content binding is invalid."""


class ExpirationError(VerificationError):
  """RCAT has expired."""


def compute_content_binding(content_id: str, nonce: bytes) -> int:
  """Computes a content binding value.

  Blinded applications invoke this on the client with a random nonce, non-
  blinded applications set the nonce to zero.

  Args:
    content_id: UTF-8 string containing the ID of content being bound. This must
      be the same ID (e.g. 11-character video ID) for 1P and 3P.
    nonce: 32 bytes nonce to be shared between 1P and 3P for content binding.
      Set to EMPTY_NONCE for non-blinded applications.

  Returns:
    64-bit content binding integer value.
  """
  if len(nonce) != _CONTENT_BINDING_NONCE_LENGTH_BYTES:
    raise ValueError('nonce must be 32 bytes')

  cb_bytes = hmac.new(
      # The content binding hash is keyed with the bytes of the client nonce
      nonce,
      # and computes a digest of the content ID UTF-8 byte values
      msg=content_id.encode(encoding='utf-8'),
      # using sha256. The first _CONTENT_BINDING_LENGTH_BYTES of the digest
      digestmod=hashlib.sha256).digest()[0:_CONTENT_BINDING_LENGTH_BYTES]
  # are returned as an integer, indicating the content binding value.
  return int.from_bytes(cb_bytes, 'little')


class Issuer:
  """The Issuer (first party) generates RCATs that are sent to a Validator.

  Issuers that are blinded to the content of their clients (e.g. e2ee services)
  must compute the content binding with a client nonce.
  """

  def __init__(self, monthly_salt: bytes, issuer_id: int,
               partner_public_keyset_handle: tink.KeysetHandle,
               private_keyset_handle: tink.KeysetHandle, n: int, k: int):
    """Initialize RCAT generation.

    Args:
      monthly_salt: 32 bytes salt for user ID hashing, updated monthly.
      issuer_id: Unique ID assigned to the issuer out of band.
      partner_public_keyset_handle: Public key material for group ID encryption.
      private_keyset_handle: Key material for cohort token signing.
      n: Number of users to be assigned to groups.
      k: Target number of users per group.

    Raises:
      IssuanceInitializationError: Initialization failed (salt too small).
    """
    if len(monthly_salt) != 32:
      raise IssuanceInitializationError('monthly_salt must be 32 bytes')
    self._salt = monthly_salt
    self._issuer_id = issuer_id

    if n < 1:
      raise IssuanceInitializationError(
          'number of users to assign should be at least 1.')
    if k < 1:
      raise IssuanceInitializationError(
          'number of users per group should be at least 1.')
    elif n < k:
      raise IssuanceInitializationError(
          'number of users to assign should be greater than number of users per group.'
      )
    self._buckets = n // k
    self._partner_public_keyset_handle = partner_public_keyset_handle
    self._private_keyset_handle = private_keyset_handle

    # Refer to the RCAT protocol explainer and adjust this value as needed for
    # your environment and use-cases (1 hour is a conservative lower-bound).
    self._token_lifetime_hours = 1
    self._signer = self._private_keyset_handle.primitive(
        signature.PublicKeySign)
    self._encrypter = self._partner_public_keyset_handle.primitive(
        hybrid.HybridEncrypt)

  def generate_token(self, uid: bytes,
                     content_id: str) -> rcat_pb2.RandomizedCounterAbuseToken:
    """Generate a randomized counter abuse token.

    In the general case, we are not blinded to the content that the token
    is bound to, so we compute the content binding (done on the client for e2ee)
    and then build the token just as we do for e2ee.

    Args:
      uid: Byte representation of the user id.
      content_id: ID of the content being bound.

    Returns:
      The Randomized Counter Abuse Token.
    """
    return self.generate_token_e2ee(
        uid, compute_content_binding(content_id, EMPTY_NONCE))

  def generate_token_e2ee(
      self, uid: bytes,
      content_binding: int) -> rcat_pb2.RandomizedCounterAbuseToken:
    """Generate a randomized counter abuse token for the blinded e2ee use case.

    Accepts a byte representation of the token-requesting user ID, and the
    client-provided content binding nonce.

    Args:
      uid: Byte representation of the user ID
      content_binding: Client-provided content binding.

    Returns:
      The Randomized Counter Abuse Token.

    Raises:
      EncryptionError: An error occurred while encrypting the token.
      SigningError: An error occurred while signing the ciphertext.
    """
    token_lifetime = datetime.timedelta(hours=self._token_lifetime_hours)
    payload = rcat_pb2.RandomizedCounterAbuseTokenPayload(
        group_id=self._compute_group_id(uid),
        content_binding=content_binding,
        expiration_utc_sec=int(
            (datetime.datetime.now() + token_lifetime).timestamp()))
    payload_bytes = payload.SerializeToString()

    try:
      # digital signature is encoded DER ASN.1 and Tink's wire format:
      # https://developers.google.com/tink/wire-format#digital_signatures
      payload_signature = self._signer.sign(payload_bytes)
    except core.TinkError as tink_err:
      raise SigningError() from tink_err

    rcat_envelope = rcat_pb2.RandomizedCounterAbuseTokenEnvelope(
        issuer_id=self._issuer_id,
        signature=payload_signature,
        payload=payload_bytes)

    try:
      # ciphertext uses Tink wire format:
      # https://developers.google.com/tink/wire-format#hybrid_public_key_encryption_hpke
      ciphertext = self._encrypter.encrypt(rcat_envelope.SerializeToString(),
                                           b'')
    except core.TinkError as tink_err:
      raise EncryptionError() from tink_err

    return rcat_pb2.RandomizedCounterAbuseToken(ciphertext=ciphertext)

  def _compute_group_id(self, uid: bytes) -> int:
    """Computes the group ID of a given user.

    Args:
      uid: byte representation of the user ID (e.g. UTF-8 codepoints)

    Returns:
      Integer group ID.
    """
    return int.from_bytes(
        hmac.new(self._salt, msg=uid, digestmod=hashlib.sha256).digest(),
        'big') % self._buckets


class Verifier:
  """RCAT Verifier (third party).

  Verifies RCATs and extracts the group ID.
  """

  def __init__(self, partner_keyset_handles: dict[int, tink.KeysetHandle],
               private_keyset_handle: tink.KeysetHandle):
    """Initialize the Verifier.

    Args:
      partner_keyset_handles: Mapping between issuer_id and Public key material
        to validate signature.
      private_keyset_handle: Private key material for decryption.
    """
    self._partner_public_keyset_handles = partner_keyset_handles
    self._private_keyset_handle = private_keyset_handle

    self._decrypter = self._private_keyset_handle.primitive(
        hybrid.HybridDecrypt)

  def process_cohort_token(self, token: rcat_pb2.RandomizedCounterAbuseToken,
                           content_id: str, nonce: bytes) -> int:
    """Validate and decrypt a randomized counter-abuse token.

    We validate the signature over the cipertext before decrypting.
    Once decrypted, we validate the content binding and expiration time
    before returning the group ID.

    Args:
      token: RandomizedCounterAbuseToken to process.
      content_id: Content to which the token is expected to be bound.
      nonce: Client nonce or 0 for the non-blinded / non-e2ee use case.

    Returns:
      Integer group ID if the token is well-formed.

    Raises:
      TokenParseError: String token could not be parsed.
      UnknownIssuerIdError: Couldn't find the issuer that issued token.
      SignatureValidationError: Ciphertext signature could not be verified.
      DecryptionError: Failed to decrypt the ciphertext.
      ContentBindingError: Content binding appears invalid.
      ExpirationError: RCAT expiration timestamp is in the past.
    """

    # The issuer signs the plaintext, and relays the signature alongside the
    # ciphertext. This requires us to decrypt the UNTRUSTED input before being
    # able to validate the sender. This is currently assumed to be safe, as the
    # RCAT protos do not have nested maps (or other opportunities for DDoS
    # attacks), but is something we should keep in mind.

    try:
      plaintext = self._decrypter.decrypt(token.ciphertext, b'')
    except core.TinkError as tink_err:
      raise DecryptionError() from tink_err
    envelope = rcat_pb2.RandomizedCounterAbuseTokenEnvelope()
    try:
      envelope.ParseFromString(plaintext)
    except message.DecodeError as decode_err:
      raise ParsingError() from decode_err

    if envelope.issuer_id not in self._partner_public_keyset_handles:
      raise UnknownIssuerIdError()
    verifier = self._partner_public_keyset_handles[
        envelope.issuer_id].primitive(signature.PublicKeyVerify)

    # Check 2. Is the signature valid?
    try:
      verifier.verify(envelope.signature, envelope.payload)
    except core.TinkError as tink_err:
      raise SignatureValidationError() from tink_err

    expected_content_binding = compute_content_binding(content_id, nonce)

    payload = rcat_pb2.RandomizedCounterAbuseTokenPayload()
    try:
      payload.ParseFromString(envelope.payload)
    except message.DecodeError as decode_err:
      raise ParsingError() from decode_err

    # Check 3. Is the content binding correct?
    if expected_content_binding != payload.content_binding:
      raise ContentBindingError()

    # Check 4. Is the token expired?
    current_timestamp = datetime.datetime.now().timestamp()
    if payload.expiration_utc_sec <= current_timestamp:
      raise ExpirationError()

    # If all checks pass, return the group ID.
    return payload.group_id
