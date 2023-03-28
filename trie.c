#include "trie.h"

struct Trie* newTrie() {
    struct Trie* trie = (struct Trie*) malloc(sizeof(struct Trie));
    trie->next[0] = trie->next[1] = NULL;
    trie->entry = NULL;
    return trie;
}

void add_route(struct Trie* root, struct route_table_entry* entry) {
    struct Trie* trie = root;
    uint32_t prefix = entry->prefix;

    uint32_t mask = 1;

    // while (prefix) {
    //     uint32_t bit = prefix & mask;

    //     printf("%u", bit);

    //     prefix >>= 1;
    // }
    // printf("\n");

    // prefix = entry->prefix;

    while (prefix > 0) {
        uint32_t bit = prefix & mask;
        if (trie->next[bit] == NULL) {
            trie->next[bit] = newTrie();
        }
        trie = trie->next[bit];
        prefix >>= 1;
    }

    if (trie->entry == NULL) {
        trie->entry = entry;
    } else if (ntohl(trie->entry->mask) < ntohl(entry->mask)) {
        trie->entry = entry;
    }
}

void print_trie(struct Trie* trie) {
    if (trie == NULL) {
        return;
    }
    if (trie->entry != NULL) {
        printf("%d.%d.%d.%d\n", (trie->entry->prefix >> 24) & 0xff, (trie->entry->prefix >> 16) & 0xff, (trie->entry->prefix >> 8) & 0xff, trie->entry->prefix & 0xff);
    }   
}

struct route_table_entry* longest_prefix_match(struct Trie* root, uint32_t ip) {
    struct Trie* trie = root;
    struct route_table_entry* entry = NULL;

    int mask = 1;

    while (trie != NULL) {
        if (trie->entry != NULL) {
            entry = trie->entry;
        }
        int bit = ip & mask;
        printf("%u", bit);
        if (trie->next[bit] == NULL) {
            break;
        }
        trie = trie->next[bit];
        ip >>= 1;
    }
    printf("final\n");

    if (entry == NULL) {
        printf("entry este null\n");
    }

    return entry;
}

void add_all_routes(struct Trie* root, struct route_table_entry* entries, int n) {
    for (int i = 0; i < n; i++) {
        add_route(root, &entries[i]);
    }
}