"""
Initialization of dependencies for Randomized Counter-Abuse Token Java reference implementation.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

def rcat_java_deps_init():
    # Initialize dependencies for Protocol buffers.
    protobuf_deps()
