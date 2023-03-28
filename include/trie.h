#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "lib.h"
#include <arpa/inet.h>

struct Trie {
    struct Trie *next[2];
    struct route_table_entry *entry;
};

struct Trie* newTrie();
void add_route(struct Trie* root, struct route_table_entry* entry);
struct route_table_entry* longest_prefix_match(struct Trie* root, uint32_t ip);
void add_all_routes(struct Trie* root, struct route_table_entry* entries, int n);
void print_trie(struct Trie* trie);
