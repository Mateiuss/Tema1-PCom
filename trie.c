#include "trie.h"

struct Trie* newTrie() {
    struct Trie* trie = (struct Trie*) malloc(sizeof(struct Trie));
    trie->next[0] = trie->next[1] = NULL;
    return trie;
}

void add_route(struct Trie* root, struct route_table_entry* entry) {
    struct Trie* trie = root;
    int prefix = entry->prefix;

    while (prefix > 0) {
        int bit = prefix & (1 << 31);
        if (trie->next[bit] == NULL) {
            trie->next[bit] = newTrie();
        }
        trie = trie->next[bit];
        prefix <<= 1;
    }

    trie->entry = entry;
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

    while (trie != NULL) {
        if (trie->entry != NULL) {
            entry = trie->entry;
        }
        int bit = ip & (1 << 31);
        trie = trie->next[bit];
        ip <<= 1;
    }

    return entry;
}

void add_all_routes(struct Trie* root, struct route_table_entry* entries, int n) {
    for (int i = 0; i < n; i++) {
        add_route(root, &entries[i]);
    }
}