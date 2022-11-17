"""
Dependencies of Randomized Counter-Abuse Token Python reference implementation.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def rcat_py_deps():
    """ Loads dependencies of Randomized Counter-Abuse Python reference implementation.
    """
    if not native.existing_rule("rules_python"):
        # Name: rules_python
        # Github: https://github.com/bazelbuild/rules_python
        # Version: 0.12.0
        # Release date: 2022-08-29
        http_archive(
            name = "rules_python",
            sha256 = "b593d13bb43c94ce94b483c2858e53a9b811f6f10e1e0eedc61073bd90e58d9c",
            strip_prefix = "rules_python-0.12.0",
            url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.12.0.tar.gz",
        )
