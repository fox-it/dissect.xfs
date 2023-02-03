import datetime
import gzip
import stat

import pytest

from dissect.xfs.xfs import XFS


def test_xfs(xfs_bin):
    xfs = XFS(xfs_bin)

    assert xfs.version == 5
    assert str(xfs.uuid) == "3fb8342e-e144-4f0c-8bd7-725e78966200"
    assert str(xfs.meta_uuid) == "00000000-0000-0000-0000-000000000000"

    root = xfs.root
    assert root.inum == 11072
    assert root.filetype == stat.S_IFDIR
    assert root.crtime == datetime.datetime(2022, 4, 22, 14, 24, 9, 264560, tzinfo=datetime.timezone.utc)
    assert root.crtime_ns == 1650637449264560000
    assert list(root.listdir().keys()) == [".", "..", "test_file", "test_dir", "test_link"]

    test_file = xfs.get("test_file")
    assert test_file.open().read() == b"test content\n"

    test_link = xfs.get("test_link")
    assert test_link.filetype == stat.S_IFLNK
    assert test_link.link == "test_dir/test_file"


@pytest.mark.parametrize(
    "image_file",
    [
        ("tests/data/xfs_symlink_test1.bin.gz"),
        ("tests/data/xfs_symlink_test2.bin.gz"),
        ("tests/data/xfs_symlink_test3.bin.gz"),
    ],
)
def test_symlinks(image_file):
    path = "/path/to/dir/with/file.ext"
    expect = b"resolved!\n"

    def resolve(node):
        while node.filetype == stat.S_IFLNK:
            node = node.link_inode
        return node

    with gzip.open(image_file, "rb") as disk:
        assert resolve(XFS(disk).get(path)).open().read() == expect
