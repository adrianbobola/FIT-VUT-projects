#ifndef IFJ20C_SYMSTACK_H
#define IFJ20C_SYMSTACK_H

#include "token.h"
#include "symtable.h"

typedef struct{
    Symtable_item** stack;
    int capacity;
    int top;
} Symstack;

/**
 * True if symbol stack is empty
 * @param symstack
 * @return
 */
bool Symstack_empty(Symstack* symstack);

/**
 * Initializes symbol stack
 * @param symstack
 */
void Symstack_init(Symstack** symstack);

/**
 * Removes top symbol from stack and returns it
 * Stack transverse ownership of symstack to caller
 * @param symstack
 * @return Symtable_item* or NULL if stack is empty
 */
Symtable_item* Symstack_pop(Symstack* symstack);

/**
 * Inserts symbol to the top of the stack. Stack capacity grows if necessary.
 * Stack takes ownership of symbol
 * @param symstack
 * @param symtable
 */
void Symstack_insert(Symstack* symstack, Symtable_item* symtable);

/**
 * Returns pointer to Symtable_item at top of the stack
 * Stack keeps ownership
 * @param symstack
 * @return non-owning Symtable_item pointer
 */
Symtable_item* Symstack_head(Symstack *symstack);

/**
 * Frees all stack memory and memory of stored objects
 * @param symstack
 */
void Symstack_dispose(Symstack **symstack);

#endif //IFJ20C_SYMSTACK_H
