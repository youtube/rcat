# RCAT CLI

This command line tool allows you to validate Randomized Counter-Abuse Token.

## Build from source

- Install [Bazel](https://docs.bazel.build/versions/master/install.html)
- Check out the code

```sh
$ git clone https://github.com/youtube/rcat.git
```

- Build

```sh
$ cd rcat/tools/cli
$ bazel build cli
```

The binary is located at `bazel-bin/cli`.

## Usage

> **Warning**
> The public / private key pairs included with this CLI tool are unsafe and 
> should only be used for testing purposes.

`cli <command> [<args>]`

Available commands:

- `validate-token`: Validates Randomized Counter-Abuse Token.

To obtain info about arguments available/required for a command, run `cli <command>` without further arguments.

- Validate a Randomized Counter-Abuse Token

```sh
$ cli validate-token \
    --verifier-private-keyset=$PWD/verifier-test-private-keyset.tink.json \
    --issuer-public-keyset=$PWD/issuer-test-public-keyset.tink.json \
    --issuer-id=1 \
    --token=<BASE64_URL_SAFE_TOKEN> \
    --content-id=<CONTENT_ID>
```

# Known limitations

## JWKS Support

We are currently only supporting Tink KeySet. If you are a YouTube partner and
using JSON Web KeySet, you can email it to us and we will be able to convert it 
into a Tink KeySet.
