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

"""Tests for rcat."""

import os
import time

import tink
from tink import signature

from absl.testing import absltest
from rcat import rcat_server as rcat
from rcat.rcat_base_test import RCATTestCase


class RCATTest(RCATTestCase):
  """Tests blinded and non-blinded issuance.

  These tests demonstrate how a token may be issued and validated, both in the
  general as well as the blinded e2ee case.
  """

  def test_nonblinded_issuer(self):
    """Demonstration of the general nonblinded issuance scheme."""
    issuer = rcat.Issuer(self._monthly_salt, self._issuer_id,
                         self._verifier_public_keyset_handle,
                         self._issuer_private_keyset_handle, self._users_n,
                         self._target_k)

    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)

    # Client calls the issuer, which uses the authenticated identity and content
    # of relevance to generate an RCAT.
    token = issuer.generate_token(self._user_id, self._content_id)

    group_id = verifier.process_cohort_token(token, self._content_id,
                                             rcat.EMPTY_NONCE)
    self.assert_group_id_valid(group_id)

  def test_blinded_issuer(self):
    """Demonstration of a blinded issuance scheme."""
    nonce = os.urandom(32)
    issuer = rcat.Issuer(self._monthly_salt, self._issuer_id,
                         self._verifier_public_keyset_handle,
                         self._issuer_private_keyset_handle, self._users_n,
                         self._target_k)
    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)

    # Client generates content binding using its local nonce.
    content_binding = rcat.compute_content_binding(self._content_id, nonce)

    # Client calls the issuer, which uses the authenticated identity and
    # client-side computed content binding to generate an RCAT.
    token = issuer.generate_token_e2ee(self._user_id, content_binding)

    # The verifier knows the content being accessed, and uses this to process
    # tne cohort token.
    group_id = verifier.process_cohort_token(token, self._content_id, nonce)
    self.assert_group_id_valid(group_id)


class RCATExceptionsTest(RCATTestCase):
  """Tests error handling for anticipated failure scenarios."""

  def test_exception_on_bad_payload_proto(self):
    """Token envelope does not parse as a proto."""
    issuer = rcat.Issuer(self._monthly_salt, self._issuer_id,
                         self._verifier_public_keyset_handle,
                         self._issuer_private_keyset_handle, self._users_n,
                         self._target_k)

    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)

    token = issuer.generate_token(self._user_id, self._content_id)
    token.ciphertext = b'not a proto'

    with self.assertRaises(rcat.DecryptionError):
      verifier.process_cohort_token(token, self._content_id, rcat.EMPTY_NONCE)

  def test_exception_on_bad_issuer_keys(self):
    """Issuer uses different keyset than what is expected by the verifier."""
    bad_issuer_keyset_handle = tink.new_keyset_handle(
        signature.signature_key_templates.ECDSA_P256)

    issuer = rcat.Issuer(self._monthly_salt, self._issuer_id,
                         self._verifier_public_keyset_handle,
                         bad_issuer_keyset_handle, self._users_n,
                         self._target_k)
    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)
    token = issuer.generate_token(self._user_id, self._content_id)

    with self.assertRaises(rcat.SignatureValidationError):
      verifier.process_cohort_token(token, self._content_id, rcat.EMPTY_NONCE)

  def test_exception_on_invalid_content_binding(self):
    issuer = rcat.Issuer(self._monthly_salt, self._issuer_id,
                         self._verifier_public_keyset_handle,
                         self._issuer_private_keyset_handle, self._users_n,
                         self._target_k)
    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)
    token = issuer.generate_token(self._user_id, self._content_id)
    with self.assertRaises(rcat.ContentBindingError):
      verifier.process_cohort_token(token, 'Different content!',
                                    rcat.EMPTY_NONCE)

  def test_exception_on_token_with_wrong_issuer_id(self):
    issuer = rcat.Issuer(self._monthly_salt, 0,
                         self._verifier_public_keyset_handle,
                         self._issuer_private_keyset_handle, self._users_n,
                         self._target_k)
    token = issuer.generate_token(self._user_id, self._content_id)
    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)
    with self.assertRaises(rcat.UnknownIssuerIdError):
      verifier.process_cohort_token(token, self._content_id, rcat.EMPTY_NONCE)

  def test_exception_on_token_expired(self):
    issuer = rcat.Issuer(self._monthly_salt, self._issuer_id,
                         self._verifier_public_keyset_handle,
                         self._issuer_private_keyset_handle, self._users_n,
                         self._target_k)
    issuer._token_lifetime_hours = 0
    verifier = rcat.Verifier(self._issuers_to_public_keyset_handles,
                             self._verifier_private_keyset_handle)
    token = issuer.generate_token(self._user_id, self._content_id)
    time.sleep(2)
    with self.assertRaises(rcat.ExpirationError):
      verifier.process_cohort_token(token, self._content_id, rcat.EMPTY_NONCE)


if __name__ == '__main__':
  absltest.main()
