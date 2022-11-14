"""
Initializing dependency for Randomized Counter-Abuse Token reference implementation in Python.
"""

load("@rules_python//python:pip.bzl", "pip_install")

def rcat_py_deps_init(workspace_name):
    pip_install(
        name = "rcat_py_pip_deps",
        requirements = "@" + workspace_name + "//:requirements.txt",
    )
