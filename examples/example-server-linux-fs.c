#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include "example-server-linux-fs.h"

/**
 * Build a solidus-delimited path string from node through its parents all the
 * way to the tree root.
 *
 * @param node starting tree-node from which to build the path
 * @return an allocated and null-terminated string containing the solidus-delimited path from the tree root to node; on error, returns NULL
 */
static char *build_path(const coap_node_t *node)
{
    size_t path_len = 1 /* leading solidus ('/') */ + 1 /* null-terminating '\0' */;
    path_len += node->name ? strlen(node->name) : 0;
    char *path = malloc(path_len);
    if (path == NULL) {
        return NULL;
    }
    path[0] = '/';
    memcpy(&path[1], node->name, path_len - 2);
    path[path_len - 1] = '\0'; /* must null-terminate */
    const coap_node_t *cur = node->parent;
    while (cur) {
        size_t segment_len = 1 /* leading solidus ('/') */;
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
    return path;
}

/**
 * GET handler for dynamically-generated children of ./fs.  Return the contents
 * of the specified file to the client.
 */
static void coap_fs_get(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(COAP_FMT_TEXT, ZCOAP_FMT_SENTINEL);
    char *path = build_path(node);
    if (path == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    FILE *fptr = fopen(path, "r");
    free(path); // done with this
    if (fptr == NULL) {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
        return;
    }
    char buf[4096];
    char *file_contents = NULL;
    size_t total = 0;
    while (fgets(buf, sizeof(buf), fptr))
    {
        size_t len = strlen(buf);
        char *resized = realloc(file_contents, total + len);
        if (resized == NULL)
        {
            free(file_contents);
            coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
            return;
        }
        file_contents = resized;
        memcpy(&file_contents[total], buf, len);
        total += len;
    }
    if (ferror)
    {
        coap_status_rsp(req, COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL));
    }
    else
    {
        if (total)
        {
            total -= 1; // strip '\0' before transmission
        }
        coap_content_rsp(req, COAP_CODE(COAP_SUCCESS, COAP_SUCCESS_CONTENT), COAP_FMT_STREAM, total, file_contents);
    }
    free(file_contents);
}

/**
 * Magical dynamic child-node generator for filesystem reflection.  Contruct
 * a solidus-delimited path from parent to the tree root.  ls this path in the
 * filesystem and return children for all inodes at the path.  Each child
 * recursively references coap_fs_gen.  Thus, we can reflect the entire
 * filesystem tree starting at any node.
 *
 * @param parent parent node under which to dynamically generate child nodes
 * @param allocator allocator for output child nodes.
 * @param n (out) number of children generated
 * @param children (out) allocated and dynamically populated children of the passed parent
 * @return 0 on success, an appropriate CoAP error code on failure
 */
coap_code_t __attribute__((nonnull (1, 2, 3, 4))) coap_fs_gen(const coap_node_t *parent, dnode_realloc_t reallocator, size_t * const n, coap_node_t **children)
{
    if (!parent || !reallocator || !n || !children) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    char *path = build_path(parent);
    DIR *d = opendir(path);
    free(path); // done with this
    if (!d) {
        return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
    }
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        ++*n;
        coap_node_t *resized = (*reallocator)(*children, *n * sizeof(coap_node_t));
        if (resized == NULL) {
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        *children = resized;
        coap_node_t *child = &(*children)[*n - 1];
        memset(child, 0, sizeof(*child));
        size_t filename_len = strlen(dir->d_name);
        child->dname = (*reallocator)(NULL, filename_len + 1);
        if (!child->dname) {
            return COAP_CODE(COAP_SERVER_ERR, COAP_SERVER_ERR_INTERNAL);
        }
        memcpy(child->dname, dir->d_name, filename_len + 1);
        child->name = child->dname;
        child->GET = &coap_fs_get;
        child->gen = &coap_fs_gen;
    }
    closedir(d);
    return 0;
}
