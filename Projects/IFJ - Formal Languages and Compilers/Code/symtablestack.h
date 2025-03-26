#ifndef IFJ20C_SYMTABLESTACK_H
#define IFJ20C_SYMTABLESTACK_H

#include "symtable.h"

typedef struct{
    Symtable_node_ptr* stack;
    int capacity;
    int top;
} Symtable_stack;

/**
 * Initializes symbol stack
 * @param symstack
 */
void Symtable_stack_init(Symtable_stack** symstack);

/**
 * Removes top symbol table from stack and returns it
 * Stack transverse ownership of symtable to caller
 * @param symstack
 * @return Symtable_node_ptr or NULL if stack is empty
 */
Symtable_node_ptr Symtable_stack_pop(Symtable_stack* symstack);

/**
 * Inserts symtable to the top of the stack. Stack capacity grows if necessary.
 * Stack takes ownership of symtable
 * @param symstack
 * @param symtable
 */
void Symtable_stack_insert(Symtable_stack* symstack, Symtable_node_ptr symtable);

/**
 * Returns pointer to Symtable_node_ptr at top of the stack
 * Stack keeps ownership
 * @param symstack
 * @return non-owning Symbol table pointer
 */
Symtable_node_ptr* Symtable_stack_head(Symtable_stack *symstack);

/**
 * Descends symbol stats and searches for variable
 * @param symtableStack
 * @param identifier
 * @return found variable or null
 */
Symtable_item* Symtable_stack_lookup(Symtable_stack* symtableStack, char* identifier);

/**
 * Frees all stack memory and memory of stored objects
 * @param symstack
 */
void Symtable_stack_dispose(Symtable_stack **symstack);

#endif //IFJ20C_SYMTABLESTACK_H
