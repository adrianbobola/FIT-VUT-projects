#ifndef _TOKEN_STACK_H_
#define _TOKEN_STACK_H_

#include "token.h"
#include <stdbool.h>

#define MAX_STACK 1024

typedef struct
{
    Token tokens[MAX_STACK]; /* Array of tokens */
    int top;                 /* Index of element on top of the stack */
} tTokenStack;

/**
 * Initialize stack. Set top to -1.
 * 
 * @param s pointer to stack
 * @return -1 if *s is NULL
 */
int tokenStackInit(tTokenStack *s);

/**
 * return nonzero value if stack is empty, else return 0.
 * @param s pointer to stack
 * @return 1 if *s is NULL else 0
*/
int tokenStackEmpty(const tTokenStack *s);

/**
 * Return nonzero value, if stack is full. Else return 0.
 * 
 * @param s pointer to stack
 * @return 1 if stack is full, else 0
 */
int tokenStackFull(const tTokenStack *s);

/**
 *  Set the value from top of stack in variables.
 * 
 * @param s pointer to stack
 * @param token pointer to token, which value will be set as value in stack
 * @return 1 if succes, 0 if stack is empty
*/
int tokenStackTop(const tTokenStack *s, Token *token);

/**
 * Removes the element from top of the stack
 * @param s pointer to stack
 * @return 1 if succes, 0 when stack is empty
*/
int tokenStackPop(tTokenStack *s);

/**
 * Insert element to top of the stack
 * @param s pointer to stack
 * @param token token to insert
 * @return 1 if succes, 0 when stack is empty
*/
int tokenStackPush(tTokenStack *s, Token token);

#endif //_TOKEN_STACK_H_