"""
Dependencies of Randomized Counter-Abuse Token Java reference implementation.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

MAVEN_ARTIFACTS = [
    # go/keep-sorted start
    "com.google.auto.value:auto-value:1.9",
    "com.google.crypto.tink:tink:1.7.0",
    "com.google.errorprone:error_prone_annotations:2.15.0",
    "com.google.guava:guava:31.1-jre",
    "com.google.protobuf:protobuf-java:3.21.5",
    "com.google.truth:truth:1.1.3",
    "junit:junit:4.13.2",
    # go/keep-sorted end
]

def rcat_java_deps():
    """
    Loads dependencies of Randomized Counter-Abuse Java reference implementation.
    """

    if not native.existing_rule("rules_jvm_external"):
        # Name: rules_jvm_external
        # Github: https://github.com/bazelbuild/rules_jvm_external
        # Version: 4.2
        # Release date: 2021-11-23
        http_archive(
            name = "rules_jvm_external",
            strip_prefix = "rules_jvm_external-4.2",
            sha256 = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/4.2.zip",
        )
