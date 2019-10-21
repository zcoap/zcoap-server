#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "example-server-linux-fs.h"

/**
 * Return the contents of the local file at path node->metadata to the
 * requesting client.
 *
 * This method may be used for coap_fs_gen mount point nodes and their
 * dynamically-generated children.  This may also be used for any static nodes
 * for which the implementer desires GET to return a resource from the local
 * filesystem.  All that's needed to do this is to define a coap_node_t as:
 *
 * const coap_node_t my_node = { .name "my_node_name", .GET = &coap_fs_get, .metadata = "$LOCAL_FILE_PATH };
 */
void coap_fs_get(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_DEBUG("%s: error, path is null\n", __func__);
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
 * Write the client-enclosed payload to the local file at path node->metadata.
 *
 * This method may be used for coap_fs_gen mount point nodes and their
 * dynamically-generated children.  This may also be used for any static nodes
 * for which the implementer desires PUT to write to a local filesystem
 * resource.  All that's needed to do this is to define a coap_node_t as:
 *
 * const coap_node_t my_node = { .name "my_node_name", .PUT = &coap_fs_put, .metadata = "$LOCAL_FILE_PATH };
 */
void coap_fs_put(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_DEBUG("%s: error, path is null\n", __func__);
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
 * Remove the local file at path node->metadata.
 *
 * This method may be used for coap_fs_gen mount point nodes and their
 * dynamically-generated children.  This may also be used for any static nodes
 * for which the implementer desires DEL to remove to a local filesystem
 * resource.  All that's needed to do this is to define a coap_node_t as:
 *
 * const coap_node_t my_node = { .name "my_node_name", .PUT = &coap_fs_DEL, .metadata = "$LOCAL_FILE_PATH };
 */
void coap_fs_delete(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(ZCOAP_FMT_SENTINEL);
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_DEBUG("%s: error, path is null\n", __func__);
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
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_DEL));
    }
}

/**
 * Magical dynamic child-node generator for filesystem reflection.  Dynamically
 * construct a tree of inodes at and below the path pointed to by a static
 * originator node's node->metadata.  Children are dynamically generated by
 * depth-first traversal and reflection of all inodes below the local
 * filesystem path stored at node->metadata.  In this way, we can mount
 * a local filesystem path at any URI in our CoAP server URI tree.
 *
 * To mount a filesystem path into the URI tree, simply define a node in the
 * tree as follows:
 *
 * const coap_node_t my_node = { .name "my_node_name", .GET = &coap_fs_get, .PUT = &coap_fs_put, .DEL = &coap_fs_delete, .metadata = "$LOCAL_FILE_PATH" };
 *
 * Methods defined at the static originator node (my_node in this example) are
 * copied to dynamically-genereated children, thus imparting privileges from
 * the static originator parent.  The parent may provide any combination of
 * the GET, PUT and DEL methods.  The coap_fs_xxx helper methods are
 * provided for this purpose.  However, an implementation may define its own
 * methods as well.  This is not difficult, as coap_fs_gen will enclose the
 * filesystem path in node->metadato for all recursively-generated children.
 *
 * @param parent node under which to dynamically generate child nodes
 * @param recursor recursive callback to which dynamically-created children should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 on success, an appropriate CoAP error code on failure
 */
coap_code_t
#ifdef __GNUC__
__attribute__((nonnull (1, 2)))
#endif
coap_fs_gen(const coap_node_t * const parent, coap_recurse_t recursor, const void *recursor_data)
{
    if (!parent || !recursor || !parent->metadata) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc = 0;
    const char *parent_path = parent->metadata;
    errno = 0;
    DIR *d = opendir(parent_path);
    if (!d) {
        int err = errno;
        if (err && err != ENOTDIR && err != EACCES) {
            ZCOAP_DEBUG("%s: error opening '%s'; %d (%s)\n", __func__, parent_path, err, strerror(err));
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
        const size_t parent_path_len = strlen(parent_path);
        const size_t entry_len = strlen(entry->d_name);
        const size_t child_path_len = parent_path_len + 1 /* solidus */ + entry_len;
        char child_path[child_path_len + 1 /* '\0' */];
        memcpy(child_path, parent_path, parent_path_len);
        child_path[parent_path_len] = '/';
        memcpy(&child_path[parent_path_len + 1], entry->d_name, entry_len);
        child_path[child_path_len] = '\0';
        coap_node_t child = { .name = entry->d_name, .parent = parent , .GET = parent->GET, .PUT = parent->PUT, .DEL = parent->DELETE, .gen = &coap_fs_gen, .metadata = child_path };
        if ((rc = (*recursor)(&child, recursor_data))) {
            goto coap_fs_gen_out;
        }
    }
    coap_fs_gen_out:
    closedir(d);
    return rc;
}
