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

/** Exception thrown when signing RCAT has failed. */
public final class RcatSigningException extends RcatIssuanceException {

  /** Constructs a {@code RcatSigningException} with no detail message. */
  public RcatSigningException() {}

  /**
   * Constructs a {@code RcatSigningException} with the specified detail message.
   *
   * @param message the detail message.
   */
  public RcatSigningException(String message) {
    super(message);
  }

  /**
   * Constructs a {@code RcatSigningException} with the specified detail message and cause.
   *
   * @param message the detail message (which is saved for later retrieval by the {@link
   *     #getMessage()} method).
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   *     (A {@code null} value is permitted, and indicates that the cause is nonexistent or
   *     unknown.)
   */
  public RcatSigningException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a {@code RcatSigningException} with the specified cause and a detail message of
   * {@code (cause == null ? null : cause.toString())} (which typically contains the class and
   * detail message of {@code cause}).
   *
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   *     (A {@code null} value is permitted, and indicates that the cause is nonexistent or
   *     unknown.)
   */
  public RcatSigningException(Throwable cause) {
    super(cause);
  }
}
