from __future__ import annotations

import datetime
import stat
from typing import BinaryIO

from dissect.xfs.xfs import XFS, fsb_to_bb


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
    assert sparse_start.dataruns == [(None, 400), (1392, 200)]

    sparse_hole = xfs.get("sparse_hole")
    assert sparse_hole.size == 0x258000
    assert sparse_hole.nblocks == 400
    assert sparse_hole.dataruns == [(1792, 200), (None, 200), (2192, 200)]

    sparse_end = xfs.get("sparse_end")
    assert sparse_end.size == 0x190000
    assert sparse_end.nblocks == 200
    assert sparse_end.dataruns == [(2392, 200), (None, 200)]

    sparse_all = xfs.get("sparse_all")
    assert sparse_all.size == 0x500000
    assert sparse_all.nblocks == 0
    assert sparse_all.dataruns == [(None, 1280)]


def test_xfs_bigtime(xfs_bigtime_bin: BinaryIO) -> None:
    xfs = XFS(xfs_bigtime_bin)

    assert xfs.version == 5

    test_file = xfs.get("file")
    assert test_file._has_bigtime()
    assert test_file.crtime == datetime.datetime(2023, 4, 7, 9, 15, 9, 223364, tzinfo=datetime.timezone.utc)
    assert test_file.crtime_ns == 1680858909223364005


def test_symlinks(xfs_symlink_bin: BinaryIO) -> None:
    path = "/path/to/dir/with/file.ext"

    xfs = XFS(xfs_symlink_bin)
    assert xfs.get(path).link == "../../../../other/path/source/to/my/file.ext"


def test_xfs_unwritten(xfs_unwritten_bin: BinaryIO) -> None:
    """Test that unwritten (preallocated) extents read as zeros, the same as on Linux.

    The blocks under the unwritten extent of ``prealloc.bin`` contain data of a deleted file.
    The fixture was made as root in a ``debian:13`` container (``docker run --rm --privileged``,
    ``debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6``),
    with xfsprogs 6.13.0-2+deb13u1 and Linux 6.12. All file content comes from these commands. A rebuild gives the same
    layout, but a different filesystem UUID and timestamps. The committed file has sha256
    ``c23e54e6569b6c0e27c48318c8a5c7a5ec9de5a45531faf8a0873334ec39b0c8``.

    .. code-block:: sh

        apt-get update && apt-get install -y xfsprogs
        mkdir mnt
        truncate -s 300M xfs.img
        mkfs.xfs -q -f xfs.img
        mount -o loop xfs.img mnt
        yes "stale data from a deleted file" | head -c 4M > mnt/old.txt
        sync && rm mnt/old.txt && umount mnt && mount -o loop xfs.img mnt
        fallocate -l 1M mnt/prealloc.bin
        truncate -s 192K mnt/mixed.bin
        printf 'A%.0s' $(seq 4096) | dd of=mnt/mixed.bin conv=notrunc status=none
        fallocate -o 64K -l 64K mnt/mixed.bin
        printf 'B%.0s' $(seq 4096) | dd of=mnt/mixed.bin bs=4K seek=44 conv=notrunc status=none
        umount mnt
        gzip -9 xfs.img
    """
    xfs = XFS(xfs_unwritten_bin)

    # One unwritten extent of 1 MiB
    prealloc = xfs.get("prealloc.bin")
    assert [extent[3] for extent in prealloc._iter_blocks()] == [1]
    assert prealloc.dataruns == [(None, 256)]

    # The blocks of the extent contain stale data, the stream must not return it
    _, block, _, _ = next(prealloc._iter_blocks())
    agnum, blknum = fsb_to_bb(block, prealloc.ag.sb.sb_agblklog)
    xfs.fh.seek((agnum * xfs.sb.sb_agblocks + blknum) * xfs.block_size)
    assert b"stale data from a deleted file" in xfs.fh.read(xfs.block_size)
    assert prealloc.open().read() == b"\x00" * 0x100000

    # A written block, a hole, an unwritten extent, a hole, a written block and a hole at the end
    mixed = xfs.get("mixed.bin")
    assert [extent[3] for extent in mixed._iter_blocks()] == [0, 1, 0]
    assert mixed.dataruns == [(13, 1), (None, 15), (None, 16), (None, 12), (296, 1), (None, 3)]
    assert mixed.open().read() == b"A" * 4096 + b"\x00" * (43 * 4096) + b"B" * 4096 + b"\x00" * (3 * 4096)
