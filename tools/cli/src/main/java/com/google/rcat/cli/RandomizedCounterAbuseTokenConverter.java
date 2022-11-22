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

package com.google.rcat.cli;

import com.google.common.io.BaseEncoding;
import com.google.protobuf.ExtensionRegistry;
import com.google.rcat.proto.RandomizedCounterAbuseToken;
import picocli.CommandLine.ITypeConverter;

/** Converts a URL-safe, base64-encoded string into a RandomizedCounterAbuseToken. */
final class RandomizedCounterAbuseTokenConverter
    implements ITypeConverter<RandomizedCounterAbuseToken> {
  @Override
  public RandomizedCounterAbuseToken convert(String value) throws Exception {
    return RandomizedCounterAbuseToken.parseFrom(
        BaseEncoding.base64Url().decode(value), ExtensionRegistry.getEmptyRegistry());
  }
}
