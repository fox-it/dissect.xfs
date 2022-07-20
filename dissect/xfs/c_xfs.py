import stat

from dissect import cstruct

xfs_def = """
#define XFS_SB_MAGIC                0x58465342  // 'XFSB'
#define XFS_SB_VERSION_1            1           // 5.3, 6.0.1, 6.1
#define XFS_SB_VERSION_2            2           // 6.2 - attributes
#define XFS_SB_VERSION_3            3           // 6.2 - new inode version
#define XFS_SB_VERSION_4            4           // 6.2+ - bitmask version
#define XFS_SB_VERSION_5            5           // CRC enabled filesystem
#define XFS_SB_VERSION_NUMBITS      0x000f
#define XFS_SB_VERSION_ALLFBITS     0xfff0
#define XFS_SB_VERSION_ATTRBIT      0x0010
#define XFS_SB_VERSION_NLINKBIT     0x0020
#define XFS_SB_VERSION_QUOTABIT     0x0040
#define XFS_SB_VERSION_ALIGNBIT     0x0080
#define XFS_SB_VERSION_DALIGNBIT    0x0100
#define XFS_SB_VERSION_SHAREDBIT    0x0200
#define XFS_SB_VERSION_LOGV2BIT     0x0400
#define XFS_SB_VERSION_SECTORBIT    0x0800
#define XFS_SB_VERSION_EXTFLGBIT    0x1000
#define XFS_SB_VERSION_DIRV2BIT     0x2000
#define XFS_SB_VERSION_BORGBIT      0x4000      // ASCII only case-insens.
#define XFS_SB_VERSION_MOREBITSBIT  0x8000

#define XFS_SB_VERSION2_RESERVED1BIT    0x00000001
#define XFS_SB_VERSION2_LAZYSBCOUNTBIT  0x00000002  // Superblk counters
#define XFS_SB_VERSION2_RESERVED4BIT    0x00000004
#define XFS_SB_VERSION2_ATTR2BIT        0x00000008  // Inline attr rework
#define XFS_SB_VERSION2_PARENTBIT       0x00000010  // parent pointers
#define XFS_SB_VERSION2_PROJID32BIT     0x00000080  // 32 bit project id
#define XFS_SB_VERSION2_CRCBIT          0x00000100  // metadata CRCs
#define XFS_SB_VERSION2_FTYPE           0x00000200  // inode type in dir

#define XFS_SB_FEAT_INCOMPAT_FTYPE      0x0001  // filetype in dirent
#define XFS_SB_FEAT_INCOMPAT_SPINODES   0x0002  // sparse inode chunks
#define XFS_SB_FEAT_INCOMPAT_META_UUID  0x0004  // metadata UUID

#define XFS_AGF_MAGIC               0x58414746  // 'XAGF'
#define XFS_AGI_MAGIC               0x58414749  // 'XAGI'
#define XFS_AGFL_MAGIC              0x5841464c  // 'XAFL'
#define XFS_AGF_VERSION             1
#define XFS_AGI_VERSION             1

#define XFS_AGF_MAGICNUM            0x00000001
#define XFS_AGF_VERSIONNUM          0x00000002
#define XFS_AGF_SEQNO               0x00000004
#define XFS_AGF_LENGTH              0x00000008
#define XFS_AGF_ROOTS               0x00000010
#define XFS_AGF_LEVELS              0x00000020
#define XFS_AGF_FLFIRST             0x00000040
#define XFS_AGF_FLLAST              0x00000080
#define XFS_AGF_FLCOUNT             0x00000100
#define XFS_AGF_FREEBLKS            0x00000200
#define XFS_AGF_LONGEST             0x00000400
#define XFS_AGF_BTREEBLKS           0x00000800
#define XFS_AGF_UUID                0x00001000
#define XFS_AGF_RMAP_BLOCKS         0x00002000
#define XFS_AGF_REFCOUNT_BLOCKS     0x00004000
#define XFS_AGF_REFCOUNT_ROOT       0x00008000
#define XFS_AGF_REFCOUNT_LEVEL      0x00010000
#define XFS_AGF_SPARE64             0x00020000
#define XFS_AGF_NUM_BITS            18

#define XFS_AGI_UNLINKED_BUCKETS    64

#define XFS_DINODE_MAGIC            0x494e      // 'IN'

#define XFS_DIFLAG_REALTIME         0x0001      // file's blocks come from rt area
#define XFS_DIFLAG_PREALLOC         0x0002      // file space has been preallocated
#define XFS_DIFLAG_NEWRTBM          0x0004      // for rtbitmap inode, new format
#define XFS_DIFLAG_IMMUTABLE        0x0008      // inode is immutable
#define XFS_DIFLAG_APPEND           0x0010      // inode is append-only
#define XFS_DIFLAG_SYNC             0x0020      // inode is written synchronously
#define XFS_DIFLAG_NOATIME          0x0040      // do not update atime
#define XFS_DIFLAG_NODUMP           0x0080      // do not dump
#define XFS_DIFLAG_RTINHERIT        0x0100      // create with realtime bit set
#define XFS_DIFLAG_PROJINHERIT      0x0200      // create with parents projid
#define XFS_DIFLAG_NOSYMLINKS       0x0400      // disallow symlink creation
#define XFS_DIFLAG_EXTSIZE          0x0800      // inode extent size allocator hint
#define XFS_DIFLAG_EXTSZINHERIT     0x1000      // inherit inode extent size
#define XFS_DIFLAG_NODEFRAG         0x2000      // do not reorganize/defragment
#define XFS_DIFLAG_FILESTREAM       0x4000      // use filestream allocator

enum xfs_dinode_fmt : uint8 {
    XFS_DINODE_FMT_DEV = 0x0,
    XFS_DINODE_FMT_LOCAL = 0x1,
    XFS_DINODE_FMT_EXTENTS = 0x2,
    XFS_DINODE_FMT_BTREE = 0x3,
    XFS_DINODE_FMT_UUID = 0x4,
    XFS_DINODE_FMT_RMAP = 0x5
};

#define XFS_DIR2_BLOCK_MAGIC        0x58443242  // XD2B: single block dirs
#define XFS_DIR2_DATA_MAGIC         0x58443244  // XD2D: multiblock dirs
#define XFS_DIR2_FREE_MAGIC         0x58443246  // XD2F: free index blocks
#define XFS_DIR2_DATA_FD_COUNT      3

#define XFS_DIR3_BLOCK_MAGIC        0x58444233  // XDB3: single block dirs
#define XFS_DIR3_DATA_MAGIC         0x58444433  // XDD3: multiblock dirs
#define XFS_DIR3_FREE_MAGIC         0x58444633  // XDF3: free index blocks

#define XFS_SYMLINK_MAGIC           0x58534c4d  // XSLM
#define XFS_SYMLINK_MAXLEN          1024

#define XFS_ABTB_MAGIC              0x41425442  // 'ABTB' for bno tree
#define XFS_ABTB_CRC_MAGIC          0x41423342  // 'AB3B'
#define XFS_ABTC_MAGIC              0x41425443  // 'ABTC' for cnt tree
#define XFS_ABTC_CRC_MAGIC          0x41423343  // 'AB3C'

#define XFS_IBT_MAGIC               0x49414254  // 'IABT'
#define XFS_IBT_CRC_MAGIC           0x49414233  // 'IAB3'
#define XFS_FIBT_MAGIC              0x46494254  // 'FIBT'
#define XFS_FIBT_CRC_MAGIC          0x46494233  // 'FIB3'

#define XFS_BMAP_MAGIC              0x424d4150  // 'BMAP'
#define XFS_BMAP_CRC_MAGIC          0x424d4133  // 'BMA3'

typedef uint64 xfs_ino_t;

typedef uint32 xfs_agblock_t;   // blockno in alloc. group
typedef uint32 xfs_agino_t;     // inode # within allocation grp
typedef uint32 xfs_extlen_t;    // extent length in blocks
typedef uint32 xfs_agnumber_t;  // allocation group number
typedef int32  xfs_extnum_t;    // # of extents in a file
typedef int16  xfs_aextnum_t;   // # extents in an attribute fork
typedef int64  xfs_fsize_t;     // bytes in a file
typedef uint64 xfs_ufsize_t;    // unsigned bytes in a file

typedef int32  xfs_suminfo_t;   // type of bitmap summary info
typedef uint32 xfs_rtword_t;    // word type for bitmap manipulations

typedef int64  xfs_lsn_t;       // log sequence number
typedef int32  xfs_tid_t;       // transaction identifier

typedef uint32 xfs_dablk_t;     // dir/attr block number (in file)
typedef uint32 xfs_dahash_t;    // dir/attr hash value

typedef uint64 xfs_fsblock_t;   // blockno in filesystem (agno|agbno)
typedef uint64 xfs_rfsblock_t;  // blockno in filesystem (raw)
typedef uint64 xfs_rtblock_t;   // extent (block) in realtime area
typedef uint64 xfs_fileoff_t;   // block number in a file
typedef uint64 xfs_filblks_t;   // number of blocks in a file

typedef int64 xfs_srtblock_t;  // signed version of xfs_rtblock_t
typedef int64  xfs_sfiloff_t;    // signed block number in a file

typedef struct xfs_timestamp {
    uint32  t_sec;      /* timestamp seconds */
    uint32  t_nsec;     /* timestamp nanoseconds */
} xfs_timestamp_t;

struct xfs_sb {
    uint32          sb_magicnum;        /* magic number == XFS_SB_MAGIC */
    uint32          sb_blocksize;       /* logical block size, bytes */
    xfs_rfsblock_t  sb_dblocks;         /* number of data blocks */
    xfs_rfsblock_t  sb_rblocks;         /* number of realtime blocks */
    xfs_rtblock_t   sb_rextents;        /* number of realtime extents */
    char            sb_uuid[16];        /* user-visible file system unique id */
    xfs_fsblock_t   sb_logstart;        /* starting block of log if internal */
    xfs_ino_t       sb_rootino;         /* root inode number */
    xfs_ino_t       sb_rbmino;          /* bitmap inode for realtime extents */
    xfs_ino_t       sb_rsumino;         /* summary inode for rt bitmap */
    xfs_agblock_t   sb_rextsize;        /* realtime extent size, blocks */
    xfs_agblock_t   sb_agblocks;        /* size of an allocation group */
    xfs_agnumber_t  sb_agcount;         /* number of allocation groups */
    xfs_extlen_t    sb_rbmblocks;       /* number of rt bitmap blocks */
    xfs_extlen_t    sb_logblocks;       /* number of log blocks */
    uint16          sb_versionnum;      /* header version == XFS_SB_VERSION */
    uint16          sb_sectsize;        /* volume sector size, bytes */
    uint16          sb_inodesize;       /* inode size, bytes */
    uint16          sb_inopblock;       /* inodes per block */
    char            sb_fname[12];       /* file system name */
    uint8           sb_blocklog;        /* log2 of sb_blocksize */
    uint8           sb_sectlog;         /* log2 of sb_sectsize */
    uint8           sb_inodelog;        /* log2 of sb_inodesize */
    uint8           sb_inopblog;        /* log2 of sb_inopblock */
    uint8           sb_agblklog;        /* log2 of sb_agblocks (rounded up) */
    uint8           sb_rextslog;        /* log2 of sb_rextents */
    uint8           sb_inprogress;      /* mkfs is in progress, don't mount */
    uint8           sb_imax_pct;        /* max percentage of fs for inode space */
    //
    // These fields must remain contiguous.  If you really
    // want to change their layout, make sure you fix the
    // code in xfs_trans_apply_sb_deltas().
    //
    uint64          sb_icount;          /* allocated inodes */
    uint64          sb_ifree;           /* free inodes */
    uint64          sb_fdblocks;        /* free data blocks */
    uint64          sb_frextents;       /* free realtime extents */
    //
    // End contiguous fields.
    //
    xfs_ino_t       sb_uquotino;        /* user quota inode */
    xfs_ino_t       sb_gquotino;        /* group quota inode */
    uint16          sb_qflags;          /* quota flags */
    uint8           sb_flags;           /* misc. flags */
    uint8           sb_shared_vn;       /* shared version number */
    xfs_extlen_t    sb_inoalignmt;      /* inode chunk alignment, fsblocks */
    uint32          sb_unit;            /* stripe or raid unit */
    uint32          sb_width;           /* stripe or raid width */
    uint8           sb_dirblklog;       /* log2 of dir block size (fsbs) */
    uint8           sb_logsectlog;      /* log2 of the log sector size */
    uint16          sb_logsectsize;     /* sector size for the log, bytes */
    uint32          sb_logsunit;        /* stripe unit size for the log */
    uint32          sb_features2;       /* additional feature bits */

    //
    // bad features2 field as a result of failing to pad the sb structure to
    // 64 bits. Some machines will be using this field for features2 bits.
    // Easiest just to mark it bad and not use it for anything else.
    //
    // This is not kept up to date in memory, it is always overwritten by
    // the value in sb_features2 when formatting the incore superblock to
    // the disk buffer.
    //
    uint32          sb_bad_features2;

    // version 5 superblock fields start here

    // feature masks
    uint32          sb_features_compat;
    uint32          sb_features_ro_compat;
    uint32          sb_features_incompat;
    uint32          sb_features_log_incompat;

    uint32          sb_crc;             /* superblock crc */
    xfs_extlen_t    sb_spino_align;     /* sparse inode chunk alignment */

    xfs_ino_t       sb_pquotino;        /* project quota inode */
    xfs_lsn_t       sb_lsn;             /* last write sequence */
    char            sb_meta_uuid[16];   /* metadata file system unique id */
};

struct xfs_agf {
    //
    // Common allocation group header information
    //
    uint32          agf_magicnum;       /* magic number == XFS_AGF_MAGIC */
    uint32          agf_versionnum;     /* header version == XFS_AGF_VERSION */
    uint32          agf_seqno;          /* sequence # starting from 0 */
    uint32          agf_length;         /* size in blocks of a.g. */
    //
    // Freespace and rmap information
    //
    uint32          agf_roots[2];   /* root blocks */
    uint32          agf_spare0;
    uint32          agf_levels[2];  /* btree levels */
    uint32          agf_spare1;

    uint32          agf_flfirst;        /* first freelist block's index */
    uint32          agf_fllast;         /* last freelist block's index */
    uint32          agf_flcount;        /* count of blocks in freelist */
    uint32          agf_freeblks;       /* total free blocks */

    uint32          agf_longest;        /* longest free space */
    uint32          agf_btreeblks;      /* # of blocks held in AGF btrees */
    char            agf_uuid[16];       /* uuid of filesystem */

    uint32          agf_rmap_blocks;        /* rmapbt blocks used */
    uint32          agf_refcount_blocks;    /* refcountbt blocks used */

    uint32          agf_refcount_root;  /* refcount tree root block */
    uint32          agf_refcount_level; /* refcount btree levels */

    //
    // reserve some contiguous space for future logged fields before we add
    // the unlogged fields. This makes the range logging via flags and
    // structure offsets much simpler.
    //
    uint64          agf_spare64[14];

    // unlogged fields, written during buffer writeback.
    uint64          agf_lsn;            /* last write sequence */
    uint32          agf_crc;            /* crc of agf sector */
    uint32          agf_spare2;

    // structure must be padded to 64 bit alignment
};

struct xfs_agi {
    //
    // Common allocation group header information
    //
    uint32          agi_magicnum;       /* magic number == XFS_AGI_MAGIC */
    uint32          agi_versionnum;     /* header version == XFS_AGI_VERSION */
    uint32          agi_seqno;          /* sequence # starting from 0 */
    uint32          agi_length;         /* size in blocks of a.g. */
    //
    // Inode information
    // Inodes are mapped by interpreting the inode number, so no
    // mapping data is needed here.
    //
    uint32          agi_count;          /* count of allocated inodes */
    uint32          agi_root;           /* root of inode btree */
    uint32          agi_level;          /* levels in inode btree */
    uint32          agi_freecount;      /* number of free inodes */

    uint32          agi_newino;         /* new inode just allocated */
    uint32          agi_dirino;         /* last directory inode chunk */
    //
    // Hash table of inodes which have been unlinked but are
    // still being referenced.
    //
    uint32          agi_unlinked[XFS_AGI_UNLINKED_BUCKETS];
    //
    // This marks the end of logging region 1 and start of logging region 2.
    //
    char            agi_uuid[16];       /* uuid of filesystem */
    uint32          agi_crc;            /* crc of agi sector */
    uint32          agi_pad32;
    uint64          agi_lsn;            /* last write sequence */

    uint32          agi_free_root;      /* root of the free inode btree */
    uint32          agi_free_level;     /* levels in free inode btree */

    // structure must be padded to 64 bit alignment
};

struct xfs_dinode {
    uint16          di_magic;           /* inode magic # = XFS_DINODE_MAGIC */
    uint16          di_mode;            /* mode and type of file */
    uint8           di_version;         /* inode version */
    uint8           di_format;          /* format of di_c data */
    uint16          di_onlink;          /* old number of links to file */
    uint32          di_uid;             /* owner's user id */
    uint32          di_gid;             /* owner's group id */
    uint32          di_nlink;           /* number of links to file */
    uint16          di_projid_lo;       /* lower part of owner's project id */
    uint16          di_projid_hi;       /* higher part owner's project id */
    uint8           di_pad[6];          /* unused, zeroed space */
    uint16          di_flushiter;       /* incremented on flush */
    xfs_timestamp_t di_atime;           /* time last accessed */
    xfs_timestamp_t di_mtime;           /* time last modified */
    xfs_timestamp_t di_ctime;           /* time created/inode modified */
    uint64          di_size;            /* number of bytes in file */
    uint64          di_nblocks;         /* # of direct & btree blocks used */
    uint32          di_extsize;         /* basic/minimum extent size for file */
    uint32          di_nextents;        /* number of extents in data fork */
    uint16          di_anextents;       /* number of extents in attribute fork*/
    uint8           di_forkoff;         /* attr fork offs, <<3 for 64b align */
    int8            di_aformat;         /* format of attr fork's data */
    uint32          di_dmevmask;        /* DMIG event mask */
    uint16          di_dmstate;         /* DMIG state info */
    uint16          di_flags;           /* random flags, XFS_DIFLAG_... */
    uint32          di_gen;             /* generation number */

    // di_next_unlinked is the only non-core field in the old dinode
    uint32          di_next_unlinked;   /* agi unlinked list ptr */

    // start of the extended dinode, writable fields
    uint32          di_crc;             /* CRC of the inode */
    uint64          di_changecount;     /* number of attribute changes */
    uint64          di_lsn;             /* flush sequence */
    uint64          di_flags2;          /* more random flags */
    uint32          di_cowextsize;      /* basic cow extent size for file */
    uint8           di_pad2[12];        /* more padding for future expansion */

    // fields only written to during inode creation
    xfs_timestamp_t di_crtime;          /* time created */
    uint64          di_ino;             /* inode number */
    char            di_uuid[16];        /* UUID of the filesystem */

    // structure must be padded to 64 bit alignment
};

struct xfs_dir2_sf_hdr {
    uint8           count;              /* count of entries */
    uint8           i8count;            /* count of 8-byte inode #s */
    uint32          parent;             /* parent dir inode number */
};

struct xfs_dir2_sf_entry {
    uint8           namelen;            /* actual name length */
    uint16          offset;             /* saved offset */
    char            name[namelen];      /* name, variable size */
    //
    // A single byte containing the file type field follows the inode
    // number for version 3 directory entries.
    //
    // A 64-bit or 32-bit inode number follows here, at a variable offset
    // after the name.
    //
};

struct xfs_dir2_data_hdr {
    uint32          magic;              /* XFS_DIR2_DATA_MAGIC or XFS_DIR2_BLOCK_MAGIC */
    uint32          bestfree[XFS_DIR2_DATA_FD_COUNT];
};

struct xfs_dir3_data_hdr {
    // Unfolded xfs_dir3_blk_hdr
    uint32          magic;              /* magic number */
    uint32          crc;                /* CRC of block */
    uint64          blkno;              /* first block of the buffer */
    uint64          lsn;                /* sequence number of last write */
    char            uuid[16];           /* filesystem we belong to */
    uint64          owner;              /* inode that owns the block */
    uint32          bestfree[3];        /* actually xfs_dir2_data_free_t best_free[XFS_DIR2_DATA_FD_COUNT] */
    uint32          pad;                /* 64 bit alignment */
};

struct xfs_dir2_data_entry {
    uint64          inumber;            /* inode number */
    uint8           namelen;            /* name length */
    char            name[namelen];      /* name bytes, no null */
    uint16          tag;                /* starting offset of us */
};

struct xfs_dir2_data_entry_ftype {
    uint64          inumber;            /* inode number */
    uint8           namelen;            /* name length */
    char            name[namelen];      /* name bytes, no null */
    uint8           ftype;           /* type of inode we point to */
    uint16          tag;                /* starting offset of us */
};

struct xfs_dir2_data_unused {
    uint16          freetag;
    uint16          length;
    uint16          tag;
};

struct xfs_dir2_leaf_entry {
    uint32          hashval;
    uint32          address;
};

struct xfs_dir2_block_tail {
    uint32          count;
    uint32          stale;
};

struct xfs_bmdr_block {
    uint16          bb_level;           /* 0 is a leaf */
    uint16          bb_numrecs;         /* current # of data records */
};

struct xfs_btree_sblock {
    uint32          bb_magic;
    uint16          bb_level;
    uint16          bb_numrecs;
    uint32          bb_leftsib;
    uint32          bb_rightsib;
};

struct xfs_btree_sblock_v5 {
    uint32          bb_magic;
    uint16          bb_level;
    uint16          bb_numrecs;
    uint32          bb_leftsib;
    uint32          bb_rightsib;
    uint64          bb_blkno;
    uint64          bb_lsn;
    char            bb_uuid[16];
    uint32          bb_owner;
    uint32          bb_crc;
};

struct xfs_btree_lblock {
    uint32          bb_magic;
    uint16          bb_level;
    uint16          bb_numrecs;
    uint64          bb_leftsib;
    uint64          bb_rightsib;
};

struct xfs_btree_lblock_v5 {
    uint32          bb_magic;
    uint16          bb_level;
    uint16          bb_numrecs;
    uint64          bb_leftsib;
    uint64          bb_rightsib;
    uint64          bb_blkno;
    uint64          bb_lsn;
    char            bb_uuid[16];
    uint64          bb_owner;
    uint32          bb_crc;
    uint32          bb_pad;
};

struct xfs_alloc_rec {
    uint32          ar_startblock;      /* starting block number */
    uint32          ar_blockcount;      /* count of free blocks */
};

struct xfs_inobt_rec {
    uint32          ir_startino;
    uint32          ir_freecount;
    uint64          ir_free;
};

struct xfs_dsymlink_hdr {
    uint32          sl_magic;
    uint32          sl_offset;
    uint32          sl_bytes;
    uint32          sl_crc;
    char            sl_uuid[16];
    uint64          sl_owner;
    uint64          sl_blkno;
    uint64          sl_lsn;
};
"""

c_xfs = cstruct.cstruct(endian=">")
c_xfs.load(xfs_def)

FILETYPES = {
    0x0: None,
    0x1: stat.S_IFREG,
    0x2: stat.S_IFDIR,
    0x3: stat.S_IFCHR,
    0x4: stat.S_IFBLK,
    0x5: stat.S_IFIFO,
    0x6: stat.S_IFSOCK,
    0x7: stat.S_IFLNK,
}

XFS_NULL = 0xFFFFFFFFFFFFFFFF
