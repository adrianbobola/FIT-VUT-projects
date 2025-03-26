#ifndef IFJ20C_SYMTABLE_H
#define IFJ20C_SYMTABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include "token.h"

#define MAXIMUM_RETURN_VALUES 10

/**
 * Variable datatype or function return type
 */
typedef enum {
    DT_VOID,
    DT_STRING,
    DT_INT,
    DT_FLOAT,
    DT_BOOL,
} Data_type;

typedef struct {
    char* identifier;
    Data_type dataType;
} Parameter;

typedef struct {
    Token token;
    Data_type dataType[MAXIMUM_RETURN_VALUES];
    bool isfunction;
    int return_values_count;
    Parameter* parameters;
    int parameter_count;
} Symtable_item;

/*
 * Frees contents of Symtable_item
 */
void free_symtable_item(Symtable_item* item);

/*
 * Binary symbol table tree node
 */
typedef struct Symtable_node {
    char *Key;
    Symtable_item *Value;
    struct Symtable_node *LPtr;
    struct Symtable_node *RPtr;
} *Symtable_node_ptr;

/*
 * Frees contents of Symtable_node_ptr
 */
void free_symtable_node(Symtable_node_ptr node);

/**
 * Initializes symbol table
 * root must be uninitialized or disposed
 * @param root pointer to symtable root node
 */
void Symtable_init(Symtable_node_ptr *root);

/**
 * Search symbol table with key.
 * @param root
 * @param key
 * @return found item or NULL if not found
 */
Symtable_item* Symtable_search(Symtable_node_ptr root, char *key);

/**
 * Inserts Symtable_item into Symbol table. If there is a value with the same key does nothing.
 * @param root
 * @param key
 * @param content
 * @returns pointer to value with matching key.
 */
Symtable_item* Symtable_insert(Symtable_node_ptr *root, char *key, Symtable_item *content);

/**
 * Removes node with matching key from table. Does nothing if value with matching key is not in the table.
 * @param root
 * @param key
 */
void Symtable_delete(Symtable_node_ptr *root, char *key);

/**
 * Frees the entire table and sets root to NULL
 * @param root
 */
void Symtable_dispose(Symtable_node_ptr *root);

/**
 * Allocates and initializes Symtable_item structure
 * @return pointer to Symtable_item
 */
Symtable_item* create_item();

/**
 * Create copy without parameters. Obtain original from global symtable.
 * @return
 */
Symtable_item* create_item_copy(Symtable_item* item);

#endif //IFJ20C_SYMTABLE_H
