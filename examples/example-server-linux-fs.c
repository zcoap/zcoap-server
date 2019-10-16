#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "example-server-linux-fs.h"

/**
 * Build a solidus-delimited path string from node through its parents all the
 * way to the mount point.  We identify the mount point as the first node in our
 * parental lineage where metadata is non-null.  node->metadata stores the mount
 * point.  With this, we can reconstruct the full filesystem path as
 *
 * @param node starting tree-node from which to build the path
 * @return an allocated and null-terminated string containing the solidus-delimited path from the tree root to node; on error, returns NULL
 */
static char *build_path(const coap_node_t *node)
{
    size_t path_len = 1 /* null-terminating '\0' */;
    char *path = calloc(path_len, sizeof(char));
    if (path == NULL) {
        return NULL;
    }
    const coap_node_t *cur = node;
    while (cur && !cur->metadata) {
        size_t segment_len = 1 /* solidus prefix ('/') */;
        segment_len += cur->name ? strlen(cur->name) : 0;
        char *resized = realloc(path, path_len + segment_len);
        if (resized == NULL) {
            free(path);
            return NULL;
        }
        path = resized;
        memmove(path + segment_len, path, path_len);
        path[0] = '/';
        memcpy(&path[1], cur->name, segment_len - 1);
        path_len += segment_len;
        cur = cur->parent;
    }
    // Now prepend node->metadata, which has our mount point.
    if (!cur || !cur->metadata) {
        free(path);
        return NULL;
    }
    const char *mnt = cur->metadata;
    size_t mnt_len = strlen(mnt);
    char *resized = realloc(path, path_len + mnt_len);
    if (resized == NULL) {
        free(path);
        return NULL;
    }
    path = resized;
    memmove(path + mnt_len, path, path_len);
    memcpy(path, mnt, mnt_len);
    return path;
}

/**
 * GET handler for dynamically-generated children of coap_fs_gen mount points.
 * Return the contents of the specified file to the client.
 */
static void coap_fs_get(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    char *path = build_path(node);
    if (path == NULL) {
        ZCOAP_DEBUG("%s: error constructing path\n", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    errno = 0;
    FILE *fptr = fopen(path, "r");
    if (fptr == NULL) {
        int err = errno;
        if (err == EACCES) {
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED));
        } else {
            ZCOAP_DEBUG("%s: error opening '%s'; %d (%s)\n", __func__, path, err, strerror(err));
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        }
        goto coap_fs_get_out;
    }
    char buf[4096];
    char *file_contents = NULL;
    size_t total = 0;
    while (fgets(buf, sizeof(buf), fptr)) {
        size_t len = strlen(buf);
        char *resized = realloc(file_contents, total + len);
        if (resized == NULL) {
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
            goto coap_fs_get_out;
        }
        file_contents = resized;
        memcpy(&file_contents[total], buf, len);
        total += len;
    }
    if (ferror(fptr)) {
        ZCOAP_DEBUG("%s: error reading '%s'\n", __func__, path);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_STREAM, total, file_contents);
    }
    coap_fs_get_out:
    if (path) {
        free(path);
    }
    if (fptr) {
        fclose(fptr);
    }
    if (file_contents) {
        free(file_contents);
    }
}

/**
 * PUT handler for dynamically-generated children of coap_fs_gen mount points.
 * Return the contents of the specified file to the client.
 */
static void coap_fs_put(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    char *path = build_path(node);
    if (path == NULL) {
        ZCOAP_DEBUG("%s: error constructing path\n", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    errno = 0;
    FILE *fptr = fopen(path, "w");
    if (fptr == NULL) {
        int err = errno;
        if (err == EACCES) {
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED));
        } else {
            ZCOAP_DEBUG("%s: error opening '%s'; %d (%s)\n", __func__, path, err, strerror(err));
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        }
        goto coap_fs_put_out;
    }
    fwrite(payload, 1, len, fptr);
    if (ferror(fptr)) {
        ZCOAP_DEBUG("%s: error writing '%s'\n", __func__, path);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
    coap_fs_put_out:
    if (path) {
        free(path);
    }
    if (fptr) {
        fclose(fptr);
    }
}

/**
 * DELETE handler for dynamically-generated children of coap_fs_gen mount points.
 * Return the contents of the specified file to the client.
 */
static void coap_fs_delete(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(ZCOAP_FMT_SENTINEL);
    char *path = build_path(node);
    if (path == NULL) {
        ZCOAP_DEBUG("%s: error constructing path\n", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    errno = 0;
    if (remove(path)) {
        int err = errno;
        if (err == EACCES) {
            ZCOAP_DEBUG("%s: error removing '%s'; %d (%s)\n", __func__, path, err, strerror(err));
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED));
        } else {
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        }
    } else {
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_DELETE));
    }
    if (path) {
        free(path);
    }
}

/**
 * Magical dynamic child-node generator for filesystem reflection.  Dynamically
 * construct a tree of inodes at and below the path pointed to by node->metadata.
 * Each child recursively references coap_fs_gen.  Thus, we can mount and
 * reflect any filesytsem node at any node in our CoAP URI tree.
 *
 * @param node parent node under which to dynamically generate child nodes
 * @param recursor recursive callback to which dynamically-created children should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 on success, an appropriate CoAP error code on failure
 */
coap_code_t __attribute__((nonnull (1, 2))) coap_fs_gen(const coap_node_t * const node, coap_recurse_t recursor, const void *recursor_data)
{
    if (!node || !recursor || !node->metadata) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc = 0;
    const char *mnt = node->metadata;
    errno = 0;
    DIR *d = opendir(mnt);
    if (!d) {
        int err = errno;
        if (err && err != ENOTDIR && err != EACCES) {
            ZCOAP_DEBUG("%s: error opening '%s'; %d (%s)\n", __func__, mnt, err, strerror(err));
            rc = COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        goto coap_fs_gen_out;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (   entry->d_type == DT_DIR
            && (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))) {
            continue;
        }
        coap_node_t child = { .name = entry->d_name, .parent = node, .GET = &coap_fs_get, .PUT = &coap_fs_put, .DELETE = &coap_fs_delete, .gen = &coap_fs_gen };
        if ((rc = (*recursor)(&child, recursor_data))) {
            goto coap_fs_gen_out;
        }
    }
    coap_fs_gen_out:
    closedir(d);
    return rc;
}
