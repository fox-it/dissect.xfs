from __future__ import annotations

import datetime
import gzip
import stat
from typing import BinaryIO

import pytest

from dissect.xfs.xfs import XFS, INode


def test_xfs(xfs_bin: BinaryIO) -> None:
    xfs = XFS(xfs_bin)

    assert xfs.version == 5
    assert xfs.block_size == 4096
    assert str(xfs.uuid) == "3fb8342e-e144-4f0c-8bd7-725e78966200"
    assert str(xfs.meta_uuid) == "00000000-0000-0000-0000-000000000000"

    root = xfs.root
    assert root.inum == 11072
    assert root.filetype == stat.S_IFDIR
    assert root.crtime == datetime.datetime(2022, 4, 22, 14, 24, 9, 264560, tzinfo=datetime.timezone.utc)
    assert root.crtime_ns == 1650637449264560000
    assert list(root.listdir().keys()) == [".", "..", "test_file", "test_dir", "test_link"]

    test_file = xfs.get("test_file")
    assert test_file.nblocks == 1
    assert test_file.open().read() == b"test content\n"

    test_link = xfs.get("test_link")
    assert test_link.nblocks == 0
    assert test_link.filetype == stat.S_IFLNK
    assert test_link.link == "test_dir/test_file"


def test_xfs_sparse(xfs_sparse_bin: BinaryIO) -> None:
    xfs = XFS(xfs_sparse_bin)

    sparse_start = xfs.get("sparse_start")
    assert sparse_start.size == 0x258000
    assert sparse_start.nblocks == 200
    assert sparse_start.dataruns() == [(None, 400), (1392, 200)]

    sparse_hole = xfs.get("sparse_hole")
    assert sparse_hole.size == 0x258000
    assert sparse_hole.nblocks == 400
    assert sparse_hole.dataruns() == [(1792, 200), (None, 200), (2192, 200)]

    sparse_end = xfs.get("sparse_end")
    assert sparse_end.size == 0x190000
    assert sparse_end.nblocks == 200
    assert sparse_end.dataruns() == [(2392, 200), (None, 200)]

    sparse_all = xfs.get("sparse_all")
    assert sparse_all.size == 0x500000
    assert sparse_all.nblocks == 0
    assert sparse_all.dataruns() == [(None, 1280)]


def test_xfs_bigtime(xfs_bigtime_bin: BinaryIO) -> None:
    xfs = XFS(xfs_bigtime_bin)

    assert xfs.version == 5

    test_file = xfs.get("file")
    assert test_file._has_bigtime()
    assert test_file.crtime == datetime.datetime(2023, 4, 7, 9, 15, 9, 223364, tzinfo=datetime.timezone.utc)
    assert test_file.crtime_ns == 1680858909223364005


@pytest.mark.parametrize(
    "image_file",
    [
        ("tests/data/xfs_symlink_test1.bin.gz"),
        ("tests/data/xfs_symlink_test2.bin.gz"),
        ("tests/data/xfs_symlink_test3.bin.gz"),
        ("tests/data/xfs_symlink_long.bin.gz"),
    ],
)
def test_symlinks(image_file: str) -> None:
    path = "/path/to/dir/with/file.ext"
    expect = b"resolved!\n"

    def resolve(node: INode) -> INode:
        while node.filetype == stat.S_IFLNK:
            node = node.link_inode
        return node

    with gzip.open(image_file, "rb") as disk:
        link_inode = resolve(XFS(disk).get(path))
        assert link_inode.nblocks == 1
        assert link_inode.open().read() == expect
