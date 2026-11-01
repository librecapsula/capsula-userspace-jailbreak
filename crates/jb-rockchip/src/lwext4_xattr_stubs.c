/*
 * Stubs for the lwext4 xattr entry points.
 *
 * ext4-lwext4 builds lwext4 without the GPL-licensed ext4_xattr.c by
 * default, but ext4.c references these functions unconditionally —
 * strict linkers (MSVC, GNU ld) fail with unresolved symbols. The tool
 * never touches xattrs, so the stubs return ENOTSUP and keep the
 * binary free of GPL code. Argument types are ABI-compatible with the
 * real prototypes in ext4_xattr.h (pointers kept opaque).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef ENOTSUP
#define ENOTSUP 134
#endif

const char *ext4_extract_xattr_name(const char *full_name,
                                    size_t full_name_len,
                                    uint8_t *name_index, size_t *name_len,
                                    bool *found)
{
    (void)full_name; (void)full_name_len;
    if (name_index) *name_index = 0;
    if (name_len) *name_len = 0;
    if (found) *found = false;
    return NULL;
}

const char *ext4_get_xattr_name_prefix(uint8_t name_index,
                                       size_t *ret_prefix_len)
{
    (void)name_index;
    if (ret_prefix_len) *ret_prefix_len = 0;
    return "";
}

int ext4_xattr_list(void *inode_ref, void *list, size_t *list_len)
{
    (void)inode_ref; (void)list;
    if (list_len) *list_len = 0;
    return ENOTSUP;
}

int ext4_xattr_get(void *inode_ref, uint8_t name_index,
                   const char *name, size_t name_len,
                   void *buf, size_t buf_len, size_t *data_len)
{
    (void)inode_ref; (void)name_index; (void)name; (void)name_len;
    (void)buf; (void)buf_len;
    if (data_len) *data_len = 0;
    return ENOTSUP;
}

int ext4_xattr_remove(void *inode_ref, uint8_t name_index,
                      const char *name, size_t name_len)
{
    (void)inode_ref; (void)name_index; (void)name; (void)name_len;
    return ENOTSUP;
}

int ext4_xattr_set(void *inode_ref, uint8_t name_index,
                   const char *name, size_t name_len,
                   const void *value, size_t value_len)
{
    (void)inode_ref; (void)name_index; (void)name; (void)name_len;
    (void)value; (void)value_len;
    return ENOTSUP;
}
