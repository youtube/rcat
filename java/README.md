# RCAT Java reference implementation

This serves as an example to implement Randomized Counter-Abuse Token protocol in Java. You can find more details in the [RCAT explainer](https://github.com/youtube/rcat/README.md).

## Prerequisites

### Install Bazel

1. Follow [the steps](https://bazel.build/install) to install Bazel.

### Clone Github repository

You will need to clone the code locally in order to build or test it.

```sh
$ git clone https://github.com/youtube/rcat
$ cd rcat/java
```

## Build

You can build the project using the following command:

```sh
rcat/java$ bazel build src/main/java/com/google/rcat:*
```

Note that this command does not produce a library or other artifact, it is only for ensuring the project compiles in your environment.

## Test

You can run all tests with the following command:

```sh
rcat/java$ bazel test src/test/java/com/google/rcat:*
```