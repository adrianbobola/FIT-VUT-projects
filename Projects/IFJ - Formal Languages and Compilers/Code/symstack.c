#include "symstack.h"

#define SYMSTACK_MIN_SIZE 10

void Symstack_init(Symstack** symstack){
    *symstack = malloc(sizeof(Symstack));
    (*symstack)->stack = malloc(sizeof(Symtable_node_ptr)*SYMSTACK_MIN_SIZE);
    (*symstack)->capacity = SYMSTACK_MIN_SIZE;
    (*symstack)->top = -1;
}

bool Symstack_empty(Symstack* symstack){
    return symstack->top == -1;
}

Symtable_item* Symstack_pop(Symstack* symstack){
    if (symstack->top == -1){
        fprintf(stderr, "Empty pop");
        return NULL;
    }
    Symtable_item* topPtr = *(symstack->stack+symstack->top);
    *(symstack->stack+symstack->top) = NULL;
    symstack->top--;
    return topPtr;
}

void Symstack_insert(Symstack* symstack, Symtable_item* item){
    if (symstack->top == symstack->capacity){
        symstack->capacity = (int)(symstack->capacity * 1.5);
        symstack->stack = realloc(symstack->stack, sizeof(Symtable_item*)*symstack->capacity);
    }
    symstack->top++;
    *(symstack->stack+symstack->top) = item;
}

Symtable_item* Symstack_head(Symstack* symstack){
    if (symstack->top == -1){
        return NULL;
    }
    return *(symstack->stack+symstack->top);
}

void Symstack_dispose(Symstack** symstack){
    for (int i = 0; i <= (*symstack)->top; ++i) {
        free_symtable_item(*((*symstack)->stack+i));
        *((*symstack)->stack+i) = NULL;
    }
    free((*symstack)->stack);
    free(*symstack);
    *symstack = NULL;
}
