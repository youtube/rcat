"""
Initialization of dependencies for Randomized Counter-Abuse Tokens reference implementation.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

def rcat_reference_impl_deps_init():
    # Initialize dependencies for Protocol buffers.
    protobuf_deps()
