/* A quick libarchive 7zip extractor, drawing heavily from
 *
 *     https://github.com/libarchive/libarchive/wiki/Examples
 */
#include <stdio.h>
#include <archive.h>

static int
copy_data(struct archive *ar, struct archive *aw)
{
	int r;
	const void *buf;
	size_t size;
	off_t offset;

	for (;;) {
		r = archive_read_data_block(ar, &buf, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r != ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buf, size, offset);
		if (r != ARCHIVE_OK) {
			fprintf(stderr, "%s\n", archive_error_string(aw));
			return (r);
		}
	}
}

static int
extract(const char *filename)
{
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;
	int flags;
	int r;

	/* Select which attributes we want to restore. */
	flags = ARCHIVE_EXTRACT_TIME;
	flags |= ARCHIVE_EXTRACT_PERM;
	flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_FFLAGS;

	a = archive_read_new();
	archive_read_support_format_7zip(a);
	archive_read_support_filter_lzma(a);
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, flags);
	archive_write_disk_set_standard_lookup(ext);
	if ((r = archive_read_open_filename(a, filename, 10240)))
		return 1;
	for (;;) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK)
			fprintf(stderr, "%s\n", archive_error_string(a));
		if (r < ARCHIVE_WARN)
			return 1;
		r = archive_write_header(ext, entry);
		if (r != ARCHIVE_OK)
			fprintf(stderr, "%s\n", archive_error_string(ext));
		else if (archive_entry_size(entry) > 0) {
			copy_data(a, ext);
			if (r != ARCHIVE_OK)
				fprintf(stderr, "%s\n", archive_error_string(ext));
			if (r < ARCHIVE_WARN)
				return 1;
		}
		r = archive_write_finish_entry(ext);
		if (r != ARCHIVE_OK)
			fprintf(stderr, "%s\n", archive_error_string(ext));
		if (r < ARCHIVE_WARN)
			return 1;
	}
	archive_read_close(a);
	archive_read_free(a);
	archive_write_close(ext);
	archive_write_free(ext);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: ./7zdecom archive.7z\n");
		printf("(the archive is extracted to the current folder)");
		return 1;
	}

	printf("extracting %s\n", argv[1]);
	return extract(argv[1]);
}
