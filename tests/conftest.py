import gzip
import os

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def gzip_file(filename):
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


@pytest.fixture
def xfs_bin():
    yield from gzip_file("data/xfs.bin.gz")


@pytest.fixture
def xfs_sparse_bin():
    yield from gzip_file("data/xfs_sparse.bin.gz")


@pytest.fixture
def xfs_bigtime_bin():
    yield from gzip_file("data/xfs_bigtime.bin.gz")
