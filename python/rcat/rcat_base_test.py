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
"""Base class for RCAT tests."""

import os

from absl.testing import parameterized
import tink
from tink import hybrid
from tink import signature


class RCATTestCase(parameterized.TestCase):
  """Base class for RCAT tests."""

  def setUp(self):
    super().setUp()
    # Number of users to assign to groups.
    self._users_n = 1000000
    # Target number of users per group.
    self._target_k = 100
    # Monthly salt for user-to-group assignment.
    self._monthly_salt = os.urandom(32)
    # Unique ID for the main issuer under test.
    self._issuer_id = 151
    # For YouTube, the content ID will be a YouTube video ID.
    self._content_id = 'dQw4w9WgXcQ'
    # The user identifier used throughout tests.
    self._user_id = b'user@foo.com'

    self.set_up_key_pairs()

  def set_up_key_pairs(self):
    self._issuer_private_keyset_handle = tink.new_keyset_handle(
        signature.signature_key_templates.ECDSA_P256)
    self._issuer_public_keyset_handle = (
        self._issuer_private_keyset_handle.public_keyset_handle())

    self._verifier_private_keyset_handle = tink.new_keyset_handle(
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM)
    self._verifier_public_keyset_handle = (
        self._verifier_private_keyset_handle.public_keyset_handle())

    self._issuers_to_public_keyset_handles = dict()
    self._issuers_to_public_keyset_handles[
        self._issuer_id] = self._issuer_public_keyset_handle

  def assert_group_id_valid(self, group_id):
    self.assertGreater(group_id, 0)
    self.assertLess(group_id, self._users_n / self._target_k)
