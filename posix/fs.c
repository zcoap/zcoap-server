#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "fs.h"

/**
 * Return the contents of the local file at path node->metadata to the
 * requesting client.
 *
 * This method may be used for coap_fs_gen mount point nodes and their
 * dynamically-generated children.  This may also be used for any static nodes
 * for which the implementer desires GET to return a resource from the local
 * filesystem.  All that's needed to do this is to define a coap_node_t as:
 *
 * const coap_node_t my_node = { .name "my_node_name", .GET = &coap_fs_get, .metadata = "$LOCAL_FILE_PATH" };
 */
void coap_fs_get(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error, path is null\n", __func__);
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
            ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error opening '%s'; %d (%s)\n", __func__, path, err, strerror(err));
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        }
        return;
    }
    char buf[4096];
    char *file_contents = NULL;
    size_t total = 0;
    while (fgets(buf, sizeof(buf), fptr)) {
        size_t _len = strlen(buf);
        char *resized = realloc(file_contents, total + _len);
        if (resized == NULL) {
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
            goto coap_fs_get_out;
        }
        file_contents = resized;
        memcpy(&file_contents[total], buf, _len);
        total += _len;
    }
    if (ferror(fptr)) {
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error reading '%s'\n", __func__, path);
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
 * Writes can be in write mode (PUT) or append mode (POST).
 */
static void coap_fs_modify(const char *mode, ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_STREAM, ZCOAP_FMT_SENTINEL);
    ZCOAP_ASSERT(!strcmp(mode, "w") || !strcmp(mode, "a"));
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error, path is null\n", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    errno = 0;
    FILE *fptr = fopen(path, mode);
    if (fptr == NULL) {
        int err = errno;
        if (err == EACCES) {
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED));
        } else {
            ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error opening '%s'; %d (%s)\n", __func__, path, err, strerror(err));
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        }
        return;
    }
    fwrite(payload, 1, len, fptr);
    if (ferror(fptr)) {
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error writing '%s'\n", __func__, path);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    } else {
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CHANGED));
    }
    if (fptr) {
        fclose(fptr);
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
 * const coap_node_t my_node = { .name "my_node_name", .PUT = &coap_fs_put, .metadata = "$LOCAL_FILE_PATH" };
 */
void coap_fs_put(ZCOAP_METHOD_SIGNATURE)
{
    coap_fs_modify("w", ZCOAP_METHOD_ARGS);
}

/**
 *
 * Append the client-enclosed payload to the local file at path node->metadata.
 *
 * This method may be used for coap_fs_gen mount point nodes and their
 * dynamically-generated children.  This may also be used for any static nodes
 * for which the implementer desires PUT to write to a local filesystem
 * resource.  All that's needed to do this is to define a coap_node_t as:
 *
 * const coap_node_t my_node = { .name "my_node_name", .POST = &coap_fs_post, .metadata = "$LOCAL_FILE_PATH" };
 */
void coap_fs_post(ZCOAP_METHOD_SIGNATURE)
{
    coap_fs_modify("a", ZCOAP_METHOD_ARGS);
}

/**
 * Remove the local file at path node->metadata.
 *
 * This method may be used for coap_fs_gen mount point nodes and their
 * dynamically-generated children.  This may also be used for any static nodes
 * for which the implementer desires DELETE to remove a local filesystem
 * resource.  All that's needed to do this is to define a coap_node_t as:
 *
 * const coap_node_t my_node = { .name "my_node_name", .DEL = &coap_fs_DELETE, .metadata = "$LOCAL_FILE_PATH" };
 */
void coap_fs_delete(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(ZCOAP_FMT_SENTINEL);
    const char *path = node->metadata;
    if (path == NULL) {
        ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error, path is null\n", __func__);
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    errno = 0;
    if (remove(path)) {
        int err = errno;
        if (err == EACCES) {
            ZCOAP_LOG(ZCOAP_LOG_DEBUG, "%s: error removing '%s'; %d (%s)\n", __func__, path, err, strerror(err));
            coap_status_rsp(req, COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_METHOD_NOT_ALLOWED));
        } else {
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        }
    } else {
        coap_status_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_DEL));
    }
}

/**
 * Produce a properly formed coap_fs node below parent of the passed name.
 * A properly formed coap_fs node has a local filesystem path set at
 * node->metadata.
 *
 * Pass the dynamically-created child node to the passed recursor to continue
 * recursing.
 *
 * @param parent node under which to dynamically generate the child node
 * @param child name of the child node to create
 * @param recursor recursive callback to which dynamically-created children should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 if the caller should keep iterating, else an appropriate CoAP code
 */
coap_code_t create_coap_fs_node(const coap_node_t * const parent, const char *name, coap_recurse_t recursor, const void *recursor_data)
{
    if (!parent || !name || !recursor) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    if (   strchr(name, '/') // Path segment injection is impermissible!
        || !strcmp(name, "..") // Navigation up the tree is impermissible!
        || !strcmp(name, ".")) { // Reference to self is impermissible!
        ZCOAP_LOG(ZCOAP_LOG_WARNING, "%s: illegal client path segment '%s'", __func__, name);
        return COAP_CODE(COAP_CLIENT_ERR, COAP_CLIENT_ERR_BAD_OPT);
    }
    const char *parent_path = parent->metadata;
    const size_t parent_path_len = strlen(parent_path);
    const size_t name_len= strlen(name);
    const size_t path_len = parent_path_len + 1 /* solidus */ + name_len;
    char path[path_len + 1 /* '\0' */];
    memcpy(path, parent_path, parent_path_len);
    path[parent_path_len] = '/';
    memcpy(&path[parent_path_len + 1], name, name_len);
    path[path_len] = '\0';
    coap_node_t child = { .name = name, .parent = parent , .GET = parent->GET, .PUT = parent->PUT, .POST = parent->POST, .DEL = parent->DEL, .gen = &coap_fs_gen, .metadata = path };
    return (*recursor)(&child, recursor_data);
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
 * const coap_node_t my_node = { .name "my_node_name", .GET = &coap_fs_get, .PUT = &coap_fs_put, .POST = &coap_fs_post, .DELETE = &coap_fs_delete, .metadata = "$LOCAL_PATH" };
 *
 * An originator node may also be defined with the 'wildcard' method.  We
 * provide a helper callback for this purpose.  An example use of the wildcard:
 *
 * static const coap_node_t tmp_uri = { .name = "tmp", .gen = &coap_fs_gen, .GET = &coap_fs_get, .PUT = &coap_fs_put, .POST = &coap_fs_post, .DELETE = &coap_fs_delete, .metadata = "/tmp", .wildcard = &create_coap_fs_node };
 *
 * This allows for wildcard match to the client request path, thus providing
 * a means to create nodes in the tree with PUT and POST.
 *
 * Methods referenced at the static originator node (my_node in this example)
 * are copied to dynamically-genereated children, thus imparting privileges
 * from the static originator parent.  The parent may provide any combination
 * of the GET, PUT and DELETE methods.  The coap_fs_xxx helper methods are
 * available for this purpose.  However, an implementation may define its own
 * methods as well.  This is not difficult, as coap_fs_gen will enclose the
 * filesystem path in node->metadato for all recursively-generated children.
 * An implementation-specific method will then have easy access to the local
 * filesystem path and can perform whatever local filesystem operation that
 * may be desired.
 *
 * Security considerations:
 *
 *   * The static parent-node originator imparts permissions to children by
 *     specification of allowable methods (GET, PUT, DELETE).
 *   * But, mounted paths should also have appropriate local permissions set.
 *   * Attacks escaping the mount point should be considered.
 *   * create_coap_fs_node does reject relative traversal up the filesystem
 *     tree ("../"), but for security, excecuting the server within a chroot
 *     or other jail is worh considering.
 *   * This may be particularly important when .PUT, .DELETE or .wildcard
 *     features are active.
 *
 * @param parent node under which to dynamically generate child nodes
 * @param recursor recursive callback to which dynamically-created children should be passed
 * @param recursor_data data to pass to the recursive callback function
 * @return 0 if the caller should keep iterating, else an appropriate CoAP code
 */
coap_code_t coap_fs_gen(const coap_node_t * const parent, coap_recurse_t recursor, const void *recursor_data)
{
    if (!parent || !recursor || !parent->metadata) {
        ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: illegal arguments", __func__);
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    coap_code_t rc = 0;
    const char *parent_path = parent->metadata;
    errno = 0;
    DIR *d = opendir(parent_path);
    if (!d) {
        int err = errno;
        if (err && err != ENOTDIR && err != EACCES) {
            ZCOAP_LOG(ZCOAP_LOG_ERR, "%s: error opening '%s'; %d (%s)\n", __func__, parent_path, err, strerror(err));
            rc = COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        return rc;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (   entry->d_type == DT_DIR
            && (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))) {
            continue;
        }
        if ((rc = create_coap_fs_node(parent, entry->d_name, recursor, recursor_data))) {
            break;
        }
    }
    closedir(d);
    return rc;
}
