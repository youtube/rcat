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

import com.google.common.primitives.UnsignedInteger;
import com.google.crypto.tink.KeysetHandle;
import java.nio.ByteBuffer;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

/**
 * This class is responsible for routing the control of the CLI to the appropriate command
 * implementation based on user input.
 *
 * <pre>{@code
 * bazel run :cli -- --help
 * }</pre>
 */
@Command(
    name = "cli",
    subcommands = {
      ValidateToken.class,
    })
public final class RcatCli implements Callable<Integer> {

  @Option(
      names = {"-h", "--help"},
      usageHelp = true,
      description = "Display a help message")
  private boolean helpRequested;

  @Spec CommandSpec spec;

  private CommandLine cmd;

  @Override
  public Integer call() {
    if (helpRequested) {
      cmd.usage(System.out);
      return 0;
    }
    throw new ParameterException(spec.commandLine(), "Missing subcommand.");
  }

  private int executeSubcommand(String... args) {
    cmd =
        new CommandLine(this)
            .registerConverter(ByteBuffer.class, new Base64UrlByteBufferConverter())
            .registerConverter(KeysetHandle.class, new KeysetHandleConverter())
            .registerConverter(UnsignedInteger.class, new UnsignedIntegerConverter());
    return cmd.execute(args);
  }

  public static void main(String[] args) {
    RcatCli cli = new RcatCli();
    int exitCode = cli.executeSubcommand(args);
    System.exit(exitCode);
  }
}
