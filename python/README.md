# RCAT Python reference implementation

This serves as an example to implement Randomized Counter-Abuse Token protocol in Python. You can find more details in the [RCAT explainer](https://github.com/youtube/rcat/README.md).

## Prerequisites

The codebase assumes Python 3.10+.

### Install Bazel

1. Follow [the steps](https://bazel.build/install) to install Bazel.

### Clone Github repository

You will need to clone the code locally in order to build or test it.

```sh
$ git clone https://github.com/youtube/rcat
$ cd rcat/python
```

## Build

You can build the project using the following command:

```sh
rcat/python$ bazel build rcat:rcat_server
```

Note that this command does not produce a library or other artifact, it is only for ensuring the project compiles in your environment.

## Test

You can run all tests with the following command:

```sh
rcat/python$ bazel test rcat:*
```