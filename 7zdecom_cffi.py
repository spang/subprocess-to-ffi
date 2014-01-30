#!/usr/bin/env python
#
# Python port of 7zdecom.c, using cffi.

import sys
import argparse

from cffi import FFI

# hardcode these for simplicity
ARCHIVE_OK = 0
ARCHIVE_EOF = 1
ARCHIVE_WARN = -20
ARCHIVE_EXTRACT_TIME = 0x0004
ARCHIVE_EXTRACT_PERM = 0x0002
ARCHIVE_EXTRACT_ACL = 0x0020
ARCHIVE_EXTRACT_FFLAGS = 0x0040

def setup_cffi_libarchive():
    ffi = FFI()

    # NOTE: This is ABI-dependent but doesn't require a C compiler.
    # This code was written against libarchive 3.1.2-7 from Debian.
    lib = ffi.dlopen('libarchive.so.13')

    # describe the data type and function prototypes to cffi. god this was
    # tedious.
    ffi.cdef("""
typedef unsigned long int dev_t;
typedef long int off_t;
typedef unsigned int mode_t;
struct archive_string {
	char	*s;  /* Pointer to the storage */
	size_t	 length; /* Length of 's' in characters */
	size_t	 buffer_length; /* Length of malloc-ed storage in bytes. */
};

struct archive_vtable {
	int	(*archive_close)(struct archive *);
	int	(*archive_free)(struct archive *);
	int	(*archive_write_header)(struct archive *,
	    struct archive_entry *);
	int	(*archive_write_finish_entry)(struct archive *);
	ssize_t	(*archive_write_data)(struct archive *,
	    const void *, size_t);
	ssize_t	(*archive_write_data_block)(struct archive *,
	    const void *, size_t, int64_t);

	int	(*archive_read_next_header)(struct archive *,
	    struct archive_entry **);
	int	(*archive_read_next_header2)(struct archive *,
	    struct archive_entry *);
	int	(*archive_read_data_block)(struct archive *,
	    const void **, size_t *, int64_t *);

	int	(*archive_filter_count)(struct archive *);
	int64_t (*archive_filter_bytes)(struct archive *, int);
	int	(*archive_filter_code)(struct archive *, int);
	const char * (*archive_filter_name)(struct archive *, int);
};

struct archive {
	unsigned int	magic;
	unsigned int	state;
	struct archive_vtable *vtable;
	int		  archive_format;
	const char	 *archive_format_name;
	int	  compression_code;	/* Currently active compression. */
	const char *compression_name;
	int		  file_count;
	int		  archive_error_number;
	const char	 *error;
	struct archive_string	error_string;
	char *current_code;
	unsigned current_codepage; /* Current ACP(ANSI CodePage). */
	unsigned current_oemcp; /* Current OEMCP(OEM CodePage). */
	struct archive_string_conv *sconv;
};
struct archive_wstring {
	wchar_t	*s;  /* Pointer to the storage */
	size_t	 length; /* Length of 's' in characters */
	size_t	 buffer_length; /* Length of malloc-ed storage in bytes. */
};
struct archive_mstring {
	struct archive_string aes_mbs;
	struct archive_string aes_utf8;
	struct archive_wstring aes_wcs;
	struct archive_string aes_mbs_in_locale;
	int aes_set;
};
struct archive_acl_entry {
	struct archive_acl_entry *next;
	int	type;			/* E.g., access or default */
	int	tag;			/* E.g., user/group/other/mask */
	int	permset;		/* r/w/x bits */
	int	id;			/* uid/gid for user/group */
	struct archive_mstring name;		/* uname/gname */
};
struct archive_acl {
	mode_t		mode;
	struct archive_acl_entry	*acl_head;
	struct archive_acl_entry	*acl_p;
	int		 acl_state;	/* See acl_next for details. */
	wchar_t		*acl_text_w;
	char		*acl_text;
	int		 acl_types;
};
struct archive_entry {
	struct archive *archive;
	void *stat;
	int  stat_valid; /* Set to 0 whenever a field in aest changes. */
	struct aest {
		int64_t		aest_atime;
		uint32_t	aest_atime_nsec;
		int64_t		aest_ctime;
		uint32_t	aest_ctime_nsec;
		int64_t		aest_mtime;
		uint32_t	aest_mtime_nsec;
		int64_t		aest_birthtime;
		uint32_t	aest_birthtime_nsec;
		int64_t		aest_gid;
		int64_t		aest_ino;
		uint32_t	aest_nlink;
		uint64_t	aest_size;
		int64_t		aest_uid;
		int		aest_dev_is_broken_down;
		dev_t		aest_dev;
		dev_t		aest_devmajor;
		dev_t		aest_devminor;
		int		aest_rdev_is_broken_down;
		dev_t		aest_rdev;
		dev_t		aest_rdevmajor;
		dev_t		aest_rdevminor;
	} ae_stat;
	int ae_set; /* bitmap of fields that are currently set */
	struct archive_mstring ae_fflags_text;	/* Text fflags per fflagstostr(3) */
	unsigned long ae_fflags_set;		/* Bitmap fflags */
	unsigned long ae_fflags_clear;
	struct archive_mstring ae_gname;		/* Name of owning group */
	struct archive_mstring ae_hardlink;	/* Name of target for hardlink */
	struct archive_mstring ae_pathname;	/* Name of entry */
	struct archive_mstring ae_symlink;		/* symlink contents */
	struct archive_mstring ae_uname;		/* Name of owner */
	struct archive_mstring ae_sourcepath;	/* Path this entry is sourced from. */
	void *mac_metadata;
	size_t mac_metadata_size;
	struct archive_acl    acl;
	struct ae_xattr *xattr_head;
	struct ae_xattr *xattr_p;
	struct ae_sparse *sparse_head;
	struct ae_sparse *sparse_tail;
	struct ae_sparse *sparse_p;
	char		 strmode[12];
};

    struct archive * archive_read_new(void);
    int archive_read_support_format_7zip(struct archive *);
    int archive_read_support_filter_lzma(struct archive *);
    struct archive * archive_write_disk_new(void);
    int archive_write_disk_set_options(struct archive *, int flags);
    int archive_write_disk_set_standard_lookup(struct archive *);
    int archive_read_open_filename(struct archive *, const char *filename, size_t block_size);
    int archive_read_next_header(struct archive *, struct archive_entry **);
    const char * archive_error_string(struct archive *);
    int archive_write_header(struct archive *, struct archive_entry *);
    int64_t archive_entry_size(struct archive_entry *a);
    int archive_write_finish_entry(struct archive *);
    int archive_read_close(struct archive *);
    int archive_read_free(struct archive *);
    int archive_write_close(struct archive *);
    int archive_write_finish(struct archive *);
    ssize_t archive_read_data_block(struct archive *, const void **buff, size_t *len, off_t *offset);
    ssize_t archive_write_data_block(struct archive *, const void *, size_t size, int64_t offset);
    """)
    return ffi, lib

def copy_data(ffi, lib, read_archive, write_archive):
    buf = ffi.new('const void *')
    size = ffi.new('size_t size')
    offset = ffi.new('off_t offset')
    while True:
        r = lib.archive_read_data_block(read_archive, ffi.addressof(buf),
                ffi.addressof(size), ffi.addressof(offset))
        if r == ARCHIVE_EOF:
            return
        if r != ARCHIVE_OK:
            raise RuntimeError(lib.archive_error_string(read_archive))

        r = lib.archive_write_data_block(write_archive, buf, size, offset)
        if r != ARCHIVE_OK:
            raise RuntimeError(lib.archive_error_string(write_archive))

def extract(ffi, lib, archive_filename):
    a = ffi.new('struct archive *')
    ext = ffi.new('struct archive *')
    entry = ffi.new('struct archive_entry *')

    flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | \
            ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS

    a = lib.archive_read_new()
    lib.archive_read_support_format_7zip(a)
    lib.archive_read_support_filter_lzma(a)
    ext = lib.archive_write_disk_new()
    lib.archive_write_disk_set_options(ext, flags)
    lib.archive_write_disk_set_standard_lookup(ext)
    r = lib.archive_read_open_filename(a, archive_filename, 10240)
    if r != 0:
        raise RuntimeError
    while True:
        print entry
        r = lib.archive_read_next_header(a, ffi.addressof(entry))
        if r == ARCHIVE_EOF:
            break
        if r != ARCHIVE_OK:
            print >>sys.stderr, lib.archive_error_string(a)
        if r < ARCHIVE_WARN:
            raise RuntimeError
        r = lib.archive_write_header(ext, entry);
        if r != ARCHIVE_OK:
            print >>sys.stderr, lib.archive_error_string(ext)
        elif (lib.archive_entry_size(entry) > 0):
            copy_data(a, ext)
            if r != ARCHIVE_OK:
                print >>sys.stderr, lib.archive_error_string(ext)
            if r < ARCHIVE_WARN:
                raise RuntimeError
        r = lib.archive_write_finish_entry(ext);
        if r != ARCHIVE_OK:
            print >>sys.stderr, lib.archive_error_string(ext)
        if r < ARCHIVE_WARN:
            raise RuntimeError
    lib.archive_read_close(a);
    lib.archive_read_free(a);
    lib.archive_write_close(ext);
    lib.archive_write_free(ext);

def main():
    parser = argparse.ArgumentParser(description="Extract a 7z archive")
    parser.add_argument('filename')

    args = parser.parse_args()

    ffi, lib = setup_cffi_libarchive()
    return extract(ffi, lib, args.filename)

if __name__ == '__main__':
    sys.exit(main())
