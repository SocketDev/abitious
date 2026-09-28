#ifndef ABITIOUS_H
#define ABITIOUS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t abitious_ffi_version(void);
int32_t abitious_probe(const char *path);
int32_t abitious_stat(const char *path, bool *compressed, uint64_t *logical,
                      uint64_t *physical);
int32_t abitious_compress_file(const char *path, uint64_t *before,
                               uint64_t *after);

/* probe: 0 supported, 1 already compressed, 2 unsupported, -1 error.
 * compress_file: 0 compressed, 1 no gain, 2 already compressed,
 * 3 unsupported, 4 skipped, -1 error. Size output pointers may be NULL.
 * All path arguments are NUL-terminated UTF-8 strings. */

#ifdef __cplusplus
}
#endif

#endif
