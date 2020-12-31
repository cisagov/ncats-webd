#!/usr/bin/env pytest -vs
"""Tests for ncats_webd.launch."""

# Standard Python Libraries
import os
import sys
# Using the PyPi package for backported functionality
from mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
from ncats_webd import launch

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = launch.__version__


def test_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            launch.main()
    captured = capsys.readouterr()
    assert (
        captured.out == "{}\n".format(PROJECT_VERSION)
    ), "standard output by '--version' should agree with module.__version__"


def test_running_as_module(capsys):
    """Verify that the __main__.py file loads correctly."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            # F401 is a "Module imported but unused" warning. This import
            # emulates how this project would be run as a module. The only thing
            # being done by __main__ is importing the main entrypoint of the
            # package and running it, so there is nothing to use from this
            # import. As a result, we can safely ignore this warning.
            # cisagov Libraries
            import ncats_webd.__main__  # noqa: F401
    captured = capsys.readouterr()
    assert (
        captured.out == "{}\n".format(PROJECT_VERSION)
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.skipif(
    RELEASE_TAG in [None, ""], reason="this is not a release (RELEASE_TAG not set)"
)
def test_release_version():
    """Verify that release tag version agrees with the module version."""
    assert (
        RELEASE_TAG == "v{}".format(PROJECT_VERSION)
    ), "RELEASE_TAG does not match the project version"
