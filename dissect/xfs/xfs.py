import os
import io
import stat
import logging
from uuid import UUID
from functools import lru_cache

from dissect.util.stream import RangeStream, RunlistStream
from dissect.util import ts

from dissect.xfs.exceptions import (
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkUnavailableException,
    UnsupportedDataforkException,
)
from dissect.xfs.c_xfs import c_xfs, FILETYPES

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_XFS", "CRITICAL"))


class XFS:
    def __init__(self, fh):
        self.fh = fh
        self.ag = {0: AllocationGroup(self, fh, 0)}
        self.sb = self.ag[0].sb

        self.block_size = self.sb.sb_blocksize
        self.version = self.sb.sb_versionnum & c_xfs.XFS_SB_VERSION_NUMBITS
        self._has_ftype = (self.version == 5 and self.sb.sb_features_incompat & c_xfs.XFS_SB_FEAT_INCOMPAT_FTYPE) or (
            self.sb.sb_features2 & c_xfs.XFS_SB_VERSION2_FTYPE
        )
        self._has_crc = self.version == 5

        # This should be the same across all AG's
        self._inum_bits = self.sb.sb_agblklog + self.sb.sb_inopblog
        self._inum_mask = (1 << self._inum_bits) - 1
        self._inum_max = self.sb.sb_agblocks * self.sb.sb_inopblock
        # Not necessarily correct for the last AG, but doesn't harm
        self._ag_size = self.sb.sb_agblocks * self.block_size

        self._lblock_s = c_xfs.xfs_btree_lblock_v5 if self._has_crc else c_xfs.xfs_btree_lblock
        self._sblock_s = c_xfs.xfs_btree_sblock_v5 if self._has_crc else c_xfs.xfs_btree_sblock

        self.name = self.sb.sb_fname.split(b"\x00")[0].decode()
        self.uuid = UUID(bytes=self.sb.sb_uuid)
        self.meta_uuid = UUID(bytes=self.sb.sb_meta_uuid)

        self.root = self.get_inode(self.sb.sb_rootino)

    def get(self, path, node=None):
        if isinstance(path, int):
            return self.get_inode(path)

        path = path.replace("\\", "/")
        node = node if node else self.root

        parts = path.split("/")
        for i, p in enumerate(parts):
            if not p:
                continue

            while node.filetype == stat.S_IFLNK and i < len(parts):
                node = node.link_inode

            dirlist = node.listdir()
            if p not in dirlist:
                raise FileNotFoundError(f"File not found: {path}")

            node = dirlist[p]

        return node

    def get_allocation_group(self, agnum):
        if agnum not in self.ag:
            self.ag[agnum] = AllocationGroup(self, RangeStream(self.fh, agnum * self._ag_size, self._ag_size), agnum)
        return self.ag[agnum]

    def get_inode(self, absinum, *args, **kwargs):
        return self.get_relative_inode(absinum >> self._inum_bits, absinum & self._inum_mask, *args, **kwargs)

    def get_relative_inode(self, agnum, inum, *args, **kwargs):
        if agnum >= self.sb.sb_agcount:
            raise Error(f"Allocation group num exceeds number of allocation groups: {agnum} >= {self.sb.sb_agcount}")
        elif inum >= self._inum_max:
            raise Error(f"inode number exceeds number of inodes per allocation group: {inum} >= {self._inum_max}")

        return self.get_allocation_group(agnum).get_inode(inum, *args, **kwargs)

    def walk_agi(self, block, agnum):
        for record in self.walk_small_tree(block, agnum, 16, (c_xfs.XFS_IBT_MAGIC, c_xfs.XFS_IBT_CRC_MAGIC)):
            yield c_xfs.xfs_inobt_rec(record)

    def walk_extents(self, block):
        for record in self.walk_large_tree(block, 16, (c_xfs.XFS_BMAP_MAGIC, c_xfs.XFS_BMAP_CRC_MAGIC)):
            yield parse_fsblock(record)

    def walk_large_tree(self, block, leaf_size, magic=None):
        self.fh.seek(block * self.block_size)
        root = self._lblock_s(self.fh)

        for record in self._walk_large_tree(root, leaf_size, magic):
            yield record

    def walk_small_tree(self, block, agnum, leaf_size, magic=None):
        block = agnum * self.sb.sb_agblocks + block
        self.fh.seek(block * self.block_size)
        root = self._sblock_s(self.fh)

        for record in self._walk_small_tree(root, leaf_size, agnum, magic):
            yield record

    def _walk_small_tree(self, node, leaf_size, agnum, magic=None):
        fh = self.fh
        if magic and node.bb_magic not in magic:
            magic_values = ", ".join([f"0x{magic_value:x}" for magic_value in magic])
            raise Error(f"B+Tree node has invalid magic. Expected one of ({magic_values}), got 0x{node.bb_magic:x}")

        if node.bb_level == 0:
            buf = fh.read(node.bb_numrecs * leaf_size)
            for rec_num in range(node.bb_numrecs):
                yield buf[rec_num * leaf_size : (rec_num + 1) * leaf_size]
        else:
            # Pointers start around halfway, we should already be at offset len(struct)
            maxrecs = (self.block_size - len(self._sblock_s)) // 8
            fh.seek(maxrecs * 4, io.SEEK_CUR)
            ptrs = c_xfs.uint32[node.bb_numrecs](fh)
            for ptr in ptrs:
                block = agnum * self.sb.sb_agblocks + ptr
                fh.seek(block * self.block_size)

                for res in self._walk_small_tree(self._sblock_s(fh), leaf_size, agnum, magic):
                    yield res

    def _walk_large_tree(self, node, leaf_size, magic=None):
        fh = self.fh
        if magic and node.bb_magic not in magic:
            magic_values = ", ".join([f"0x{magic_value:x}" for magic_value in magic])
            raise Error(f"B+Tree node has invalid magic. Expected one of ({magic_values}), got 0x{node.bb_magic:x}")

        if node.bb_level == 0:
            buf = fh.read(node.bb_numrecs * leaf_size)
            for rec_num in range(node.bb_numrecs):
                yield buf[rec_num * leaf_size : (rec_num + 1) * leaf_size]
        else:
            # Pointers start around halfway, we should already be at offset len(struct)
            maxrecs = (self.block_size - len(self._lblock_s)) // 16
            fh.seek(maxrecs * 8, io.SEEK_CUR)
            ptrs = c_xfs.uint64[node.bb_numrecs](fh)
            for ptr in ptrs:
                agnum, blknum = fsb_to_bb(ptr, self.sb.sb_agblklog)
                block = agnum * self.sb.sb_agblocks + blknum
                fh.seek(block * self.block_size)

                for res in self._walk_tree(self._lblock_s(fh), leaf_size, magic):
                    yield res


class AllocationGroup:
    def __init__(self, xfs, fh, num):
        self.xfs = xfs
        self.fh = fh
        self.num = num

        fh.seek(0)

        self.sb = c_xfs.xfs_sb(fh)
        sb = self.sb

        if sb.sb_magicnum != c_xfs.XFS_SB_MAGIC:
            raise Error("Not a valid XFS filesystem (magic mismatch)")

        self.block_size = sb.sb_blocksize
        if self.block_size == 0 or self.block_size % 512:
            raise Error("Not a valid XFS filesystem (invalid block size)")

        # This seems to be all related to allocation
        # Do we really need to parse this?
        # fh.seek(sb.sb_sectsize * 1)
        # self.agf = c_xfs.xfs_agf(fh)

        fh.seek(sb.sb_sectsize * 2)
        self.agi = c_xfs.xfs_agi(fh)
        if self.agi.agi_magicnum != c_xfs.XFS_AGI_MAGIC:
            raise Error("Not a valid XFS filesystem (AGI magic mismatch)")

        # This should be the same across all AG's
        self._inum_bits = sb.sb_agblklog + sb.sb_inopblog
        self._inum_mask = (1 << self._inum_bits) - 1
        self._inum_max = sb.sb_agblocks * sb.sb_inopblock

    @lru_cache(1024)
    def get_inode(self, inum, filename=None, filetype=None, parent=None, lazy=False):
        inode = INode(self, inum, filename, filetype, parent=parent)

        if not lazy:
            inode._inode = inode._read_inode()

        return inode

    def walk_extents(self, fsb):
        agnum, blknum = fsb_to_bb(fsb, self.sb.sb_agblklog)
        block = agnum * self.xfs.sb.sb_agblocks + blknum
        for fs_block in self.xfs.walk_extents(block):
            yield fs_block

    def walk_agi(self):
        for inobt_record in self.xfs.walk_agi(self.agi.agi_root, self.num):
            yield inobt_record

    def walk_tree(self, fsb, magic=None, small=False):
        agnum, blknum = fsb_to_bb(fsb, self.sb.sb_agblklog)
        block = agnum * self.xfs.sb.sb_agblocks + blknum
        for record in self.xfs.walk_tree(block, magic, small):
            yield record


class INode:
    def __init__(self, ag, inum, filename=None, filetype=None, parent=None):
        self.ag = ag
        self.xfs = ag.xfs
        self.inum = inum + (ag.num << ag._inum_bits)
        self.relative_inum = inum
        self.parent = parent
        self._inode = None
        self._buf = None

        self.filename = filename
        self._filetype = filetype
        self._link = None
        self._link_inode = None

        self._dirlist = None
        self._runlist = None

    def __repr__(self):
        return f"<inode {self.inum} ({self.ag.num}:{self.relative_inum})>"

    def _read_inode(self):
        self.ag.fh.seek(self.relative_inum * self.ag.sb.sb_inodesize)
        self._buf = io.BytesIO(self.ag.fh.read(self.ag.sb.sb_inodesize))
        inode = c_xfs.xfs_dinode(self._buf)

        if inode.di_magic != c_xfs.XFS_DINODE_MAGIC:
            raise Error(f"{self!r} has invalid inode magic")

        return inode

    @property
    def inode(self):
        if not self._inode:
            self._inode = self._read_inode()
        return self._inode

    @property
    def size(self):
        return self.inode.di_size

    @property
    def filetype(self):
        if not self._filetype:

            self._filetype = stat.S_IFMT(self.inode.di_mode)
        return self._filetype

    @property
    def link(self):
        if self.filetype != stat.S_IFLNK:
            raise NotASymlinkError(f"{self!r} is not a symlink")

        if not self._link:
            if self.inode.di_format != c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL and self.xfs.version == 5:
                fh = self.open()

                header = c_xfs.xfs_dsymlink_hdr(fh)
                if header.sl_magic != c_xfs.XFS_SYMLINK_MAGIC:
                    raise NotASymlinkError(f"{self!r} has invalid symlink magic")

                self._link = fh.read(header.sl_bytes).decode()
            else:
                self._link = self.open().read(self.size).decode()
        return self._link

    @property
    def link_inode(self):
        if not self._link_inode:
            # Relative lookups work because . and .. are actual directory entries
            link = self.link
            if link.startswith("/"):
                relnode = None
            elif link.startswith("../"):
                relnode = self.parent.parent
                if relnode is None:
                    raise SymlinkUnavailableException(f"{self!r} is a symlink to another filesystem")
            else:
                relnode = self.parent
            self._link_inode = self.xfs.get(self.link, relnode)
        return self._link_inode

    @property
    def atime(self):
        return ts.from_unix_ns(self.atime_ns)

    @property
    def atime_ns(self):
        return (self.inode.di_atime.t_sec * 1000000000) + self.inode.di_atime.t_nsec

    @property
    def mtime(self):
        return ts.from_unix_ns(self.mtime_ns)

    @property
    def mtime_ns(self):
        return (self.inode.di_mtime.t_sec * 1000000000) + self.inode.di_mtime.t_nsec

    @property
    def ctime(self):
        return ts.from_unix_ns(self.ctime_ns)

    @property
    def ctime_ns(self):
        return (self.inode.di_ctime.t_sec * 1000000000) + self.inode.di_ctime.t_nsec

    @property
    def crtime(self):
        return ts.from_unix_ns(self.crtime_ns)

    @property
    def crtime_ns(self):
        return (self.inode.di_crtime.t_sec * 1000000000) + self.inode.di_crtime.t_nsec

    def listdir(self):
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        if not self._dirlist:
            dirs = {}

            buf = self.open()
            if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
                header = c_xfs.xfs_dir2_sf_hdr(buf)
                inum_s = c_xfs.uint64 if header.i8count else c_xfs.uint32

                if header.i8count:
                    header.parent = (header.parent << 32) | c_xfs.uint32(buf)

                dirs["."] = self
                dirs[".."] = self.xfs.get_inode(header.parent)

                for _ in range(header.count):
                    entry = c_xfs.xfs_dir2_sf_entry(buf)
                    fname = entry.name.decode("utf-8", "surrogateescape")
                    ftype = c_xfs.uint8(buf) if self.xfs._has_ftype else 0
                    inum = inum_s(buf)

                    ftype = FILETYPES[ftype]

                    dirs[fname] = self.xfs.get_inode(inum, fname, ftype, parent=self, lazy=True)
            elif self.inode.di_format in (
                c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
                c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
            ):
                for block_num in range(self.size // self.xfs.block_size):
                    buf.seek(block_num * self.xfs.block_size)

                    block_data = buf.read(self.xfs.block_size)
                    block = io.BytesIO(block_data)

                    block.seek(-len(c_xfs.xfs_dir2_block_tail), io.SEEK_END)
                    tail = c_xfs.xfs_dir2_block_tail(block)
                    block.seek(0)

                    if self.inode.di_nextents > 1:
                        entries_end = self.xfs.block_size
                    else:
                        entries_end = self.xfs.block_size
                        entries_end -= len(c_xfs.xfs_dir2_block_tail)
                        entries_end -= len(c_xfs.xfs_dir2_leaf_entry) * tail.count

                    if self.xfs.version == 5:
                        header = c_xfs.xfs_dir3_data_hdr(block)
                        if header.magic not in (c_xfs.XFS_DIR3_BLOCK_MAGIC, c_xfs.XFS_DIR3_DATA_MAGIC):
                            # Probably a sparse block
                            continue
                    else:
                        header = c_xfs.xfs_dir2_data_hdr(block)
                        if header.magic not in (c_xfs.XFS_DIR2_BLOCK_MAGIC, c_xfs.XFS_DIR2_DATA_MAGIC):
                            # Probably a sparse block
                            continue

                    if self.xfs._has_ftype:
                        data_entry = c_xfs.xfs_dir2_data_entry_ftype
                    else:
                        data_entry = c_xfs.xfs_dir2_data_entry

                    while True:
                        if block.tell() >= entries_end:
                            break

                        try:
                            if block_data[block.tell() : block.tell() + 2] == b"\xff\xff":
                                unused = c_xfs.xfs_dir2_data_unused(block)

                                block.read(unused.length - 6)

                                misalign = block.tell() % 8
                                if misalign:
                                    block.seek(8 - misalign, io.SEEK_CUR)

                                continue

                            entry = data_entry(block)

                            # Entries are 8 byte aligned
                            # uint64 inum | uint8 namelen | variable name | uint8 ftype | uint16 tag
                            misalign = block.tell() % 8
                            if misalign:
                                block.seek(8 - misalign, io.SEEK_CUR)
                        except EOFError:
                            break

                        inum = entry.inumber
                        if inum >> 48 == 0xFFFF:  # XFS_DIR2_DATA_FREE_TAG
                            break

                        if self.xfs._has_ftype:
                            ftype = FILETYPES[entry.ftype]
                        else:
                            ftype = None

                        fname = entry.name.decode("utf-8", "surrogateescape")

                        dirs[fname] = self.xfs.get_inode(inum, fname, ftype, parent=self, lazy=True)
            else:
                raise Error(f"{self!r} has invalid inode format for dirlist")

            self._dirlist = dirs

        return self._dirlist

    dirlist = listdir

    def datafork(self):
        offset = 0xB0 if self.inode.di_version == 0x3 else 0x64
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            size = self.size
        else:
            size = self.ag.sb.sb_inodesize - offset

        if self.inode.di_forkoff:
            size -= size - self.inode.di_forkoff * 8

        return RangeStream(self._buf, offset, size)

    def attrfork(self):
        offset = self.inode.di_forkoff * 8
        if offset == 0:
            raise Error(f"{self!r} has no extended attributes")

        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            size = self.size
        else:
            size = self.ag.sb.sb_inodesize - offset

        return RangeStream(self._buf, offset, size)

    def dataruns(self):
        if not self._runlist:
            runs = []
            run_offset = 0

            if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
                buf = self.datafork().read(self.inode.di_nextents * 16)
                for extent_num in range(self.inode.di_nextents):
                    offset, block, count, _ = parse_fsblock(buf[extent_num * 16 : (extent_num + 1) * 16])

                    # Sparse gaps
                    if offset != run_offset:
                        gap = offset - run_offset
                        runs.append((None, gap))
                        run_offset += gap

                    # Convert filesystem blocks to logical blocks
                    agnum, blknum = fsb_to_bb(block, self.ag.sb.sb_agblklog)
                    block = agnum * self.xfs.sb.sb_agblocks + blknum

                    runs.append((block, count))
                    run_offset += count
            elif self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
                # B+tree extent lists are always large trees (64bit block numbers)
                df = self.datafork()
                root = c_xfs.xfs_bmdr_block(df)

                # Pointers start around halfway
                maxrecs = (df.size - 4) // 16
                df.seek(4 + maxrecs * 8)
                ptrs = c_xfs.uint64[root.bb_numrecs](df)

                for ptr in ptrs:
                    for offset, block, count, _ in self.ag.walk_extents(ptr):
                        if offset != run_offset:
                            gap = offset - run_offset
                            runs.append((None, gap))
                            run_offset += gap

                        agnum, blknum = fsb_to_bb(block, self.ag.sb.sb_agblklog)
                        block = agnum * self.xfs.sb.sb_agblocks + blknum
                        runs.append((block, count))
                        run_offset += count

            self._runlist = runs
        return self._runlist

    def open(self):
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            return self.datafork()
        elif self.inode.di_format in (
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        ):
            return RunlistStream(self.xfs.fh, self.dataruns(), self.size, self.xfs.block_size)
        elif self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_DEV:
            raise UnsupportedDataforkException(f"{self!r} is a character/block device.")
        else:
            dinode_type = c_xfs.xfs_dinode_fmt(self.inode.di_format)
            raise UnsupportedDataforkException(f"{self!r} is an unsupported datafork: {dinode_type}")


def parse_fsblock(s):
    # MSB -> LSB
    # flag = 1 bit
    # offset = 54 bits
    # block = 52 bits
    # count = 21 bits
    l0, l1 = c_xfs.uint64[2](s)

    flag = l0 >> 63
    offset = (l0 & ((1 << 63) - 1)) >> 9
    block = (l0 & ((1 << 9) - 1)) << 43 | (l1 >> 21)
    count = l1 & ((1 << 21) - 1)

    return offset, block, count, flag


def fsb_to_bb(block, agblklog):
    agnum = block >> agblklog
    blknum = block & ((1 << agblklog) - 1)
    return agnum, blknum
