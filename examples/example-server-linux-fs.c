#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "example-server-linux-fs.h"

/**
 * GET handler for dynamically-generated children of coap_fs_gen mount points.
 * Return the contents of the specified file to the client.
 */
static void coap_fs_get(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_DEBUG("%s: path is NULL!\n", __func__);
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
        return;
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
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_DEBUG("%s: path is NULL!\n", __func__);
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
        return;
    }
    fwrite(payload, 1, len, fptr);
    if (ferror(fptr)) {
        ZCOAP_DEBUG("%s: error writing '%s'\n", __func__, path);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
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
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_DEBUG("%s: path is NULL!\n", __func__);
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
        const size_t mnt_len = strlen(mnt);
        const size_t entry_len = strlen(entry->d_name);
        const size_t path_len = mnt_len + entry_len + 1 /* '/' */;
        char path[path_len + 1 /* '/0' */];
        memcpy(path, mnt, mnt_len);
        path[mnt_len] = '/';
        memcpy(&path[mnt_len + 1], entry->d_name, entry_len);
        path[path_len] = '\0';
        coap_node_t child = { .name = entry->d_name, .parent = node, .GET = &coap_fs_get, .PUT = &coap_fs_put, .DELETE = &coap_fs_delete, .gen = &coap_fs_gen, .metadata = path };
        if ((rc = (*recursor)(&child, recursor_data))) {
            goto coap_fs_gen_out;
        }
    }
    coap_fs_gen_out:
    closedir(d);
    return rc;
}
