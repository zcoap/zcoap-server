#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include "example-server-linux-fs.h"

static struct {
    size_t n;
    char **name;
} file_listing = { 0 };


/**
 * GET handler for dynamically-generated children of ./fs.  Return the contents
 * of the specified file to the client.
 */
static void coap_fs_get(ZCOAP_METHOD_SIGNATURE)
{
    ZCOAP_METHOD_HEADER(ZCOAP_FMT_SENTINEL);
    FILE *fptr = fopen(node->name, "r");
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
 * Free our local file listing.
 */
static void free_file_listing(void)
{
    for (size_t i = 0; i < file_listing.n; ++i)
    {
        if (file_listing.name[i])
        {
            free(file_listing.name[i]);
        }
    }
    free(file_listing.name);
    memset(&file_listing, 0, sizeof(file_listing));
}

/**
 * Populate our local file listing.
 */
static void populate_file_list()
{
    free_file_listing();
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            ++file_listing.n;
            char **resized = realloc(file_listing.name, sizeof(file_listing.name[0]) * file_listing.n);
            if (resized == NULL)
            {
                free_file_listing(); // no good!  maybe log this?
                break;
            }
            file_listing.name = resized;
            size_t filename_len = strlen(dir->d_name);
            file_listing.name[file_listing.n - 1] = malloc(filename_len + 1);
            if (file_listing.name[file_listing.n - 1] == NULL)
            {
                free_file_listing(); // no good!  maybe log this?
                break;
            }
            memcpy(file_listing.name[file_listing.n - 1], dir->d_name, strlen(dir->d_name) + 1);
        }
        closedir(d);
    }
    return;
}

/**
 * Dynamic child-node generator for ./fs.  ls the current directory and add
 * a node for each file found.
 *
 * @param iterator (in/out) iterator for maintaining state during the tree traversal
 * @param object (out) location to write the dynamic child node
 * @return 0 if a child node was produced, -1 if the generator is done producing children
 */
static int coap_fs_gen(coap_meta_t *iterator, coap_node_t *object)
{
    if (!*iterator) {
        // First pass, populate file list.
        populate_file_list();
    }
    for (coap_meta_t i = *iterator; i < file_listing.n; ++i) {
        if (file_listing.name[i] && strlen(file_listing.name[i])) {
            *iterator = i + 1;
            object->name = file_listing.name[i];
            object->GET = &coap_fs_get;
            return 0;
        }
    }
    *iterator = file_listing.n;
    return -1;
}

static coap_gen_t fs_gens[] = { &coap_fs_gen, NULL };
const coap_node_t fs_uri = { .name = "fs", .gens = fs_gens };
