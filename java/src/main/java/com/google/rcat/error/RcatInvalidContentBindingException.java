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

package com.google.rcat.error;

/**
 * Exception thrown when the content binding for RCAT is invalid.
 *
 * <p>When a Randomized Counter-Abuse Token is issued, it can be binded to a nonce value which will
 * be communicated to the first-party for verification. It prevents the token from being stolen and
 * reused outside the content for which it was intended. See RCAT explainer for more details.
 */
public final class RcatInvalidContentBindingException extends RcatVerificationException {

  /** Constructs a {@code RcatInvalidContentBindingException} with no detail message. */
  public RcatInvalidContentBindingException() {}

  /**
   * Constructs a {@code RcatInvalidContentBindingException} with the specified detail message.
   *
   * @param message the detail message.
   */
  public RcatInvalidContentBindingException(String message) {
    super(message);
  }

  /**
   * Constructs a {@code RcatInvalidContentBindingException} with the specified detail message and
   * cause.
   *
   * @param message the detail message (which is saved for later retrieval by the {@link
   *     #getMessage()} method).
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   *     (A {@code null} value is permitted, and indicates that the cause is nonexistent or
   *     unknown.)
   */
  public RcatInvalidContentBindingException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a {@code RcatInvalidContentBindingException} with the specified cause and a detail
   * message of {@code (cause == null ? null : cause.toString())} (which typically contains the
   * class and detail message of {@code cause}).
   *
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   *     (A {@code null} value is permitted, and indicates that the cause is nonexistent or
   *     unknown.)
   */
  public RcatInvalidContentBindingException(Throwable cause) {
    super(cause);
  }
}
