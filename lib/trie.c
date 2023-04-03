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

struct route_table_entry* longest_prefix_match(struct Trie* root, uint32_t ip) {
    struct Trie* trie = root;
    struct route_table_entry* entry = NULL;

    int mask = 1;

    while (trie != NULL) {
        if (trie->entry != NULL) {
            entry = trie->entry;
        }
        int bit = ip & mask;
        if (trie->next[bit] == NULL) {
            break;
        }
        trie = trie->next[bit];
        ip >>= 1;
    }

    return entry;
}

void add_all_routes(struct Trie* root, struct route_table_entry* entries, int n) {
    for (int i = 0; i < n; i++) {
        add_route(root, &entries[i]);
    }
}