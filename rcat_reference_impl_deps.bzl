"""
Cross-languages dependencies for Randomized Counter-Abuse Tokens reference implementation.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def rcat_reference_impl_deps():
    if not native.existing_rule("com_google_protobuf"):
        # Name: Protobuf
        # Github: https://github.com/protocolbuffers/protobuf
        # Version: 21.5
        # Release date: 2022-08-09
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-21.5",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/v21.5.zip"],
            sha256 = "468a16f50694822291da57e304197f5322607dbed1a9d93192ff18de642c6cac",
        )
