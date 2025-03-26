#include "token_stack.h"
#include <stdio.h>
#include <stdlib.h>
#include "string.h"

int STACK_SIZE = MAX_STACK;

/**
 * Initialize stack. Set top to -1.
 * 
 * @param s pointer to stack
 * @return -1 if *s is NULL
 */
int tokenStackInit(tTokenStack *s)
{

    if (s == NULL)
    {
        return -1;
    }

    //Identifies, that stack is empty
    s->top = -1;

    return 1;
}

/**
 * return nonzero value if stack is empty, else return 0.
 * @param s pointer to stack
 * @return 1 if *s is NULL else 0
*/
int tokenStackEmpty(const tTokenStack *s)
{

    return s->top == -1;
}

/**
 * Return nonzero value, if stack is full. Else return 0.
 * 
 * @param s pointer to stack
 * @return 1 if stack is full, else 0
 */
int tokenStackFull(const tTokenStack *s)
{

    return (s->top + 1) == STACK_SIZE;
}

/**
 *  Set the value from top of stack in variables.
 * 
 * @param s pointer to stack
 * @param token pointer to token, which value will be set as value in stack
 * @return 1 if succes, 0 if stack is empty
*/
int tokenStackTop(const tTokenStack *s, Token *token)
{

    if (tokenStackEmpty(s))
    {
        return 0;
    }

    //Insert the value from top of the stack into the variable c
    *token = s->tokens[s->top];
    return 1;
}

/**
 * Removes the element from top of the stack
 * @param s pointer to stack
 * @return 1 if succes, 0 when stack is empty
*/
int tokenStackPop(tTokenStack *s)
{

    if (tokenStackEmpty(s))
    {
        return 0;
    }

    s->top -= 1;

    return 1;
}

/**
 * Insert element to top of the stack
 * @param s pointer to stack
 * @param token token to insert
 * @return 1 if succes, 0 when stack is empty
*/
int tokenStackPush(tTokenStack *s, Token token)
{

    if (tokenStackFull(s))
    {
        return 0;
    }

    //increment top of stack
    s->top += 1;
    //insert element on top of stack
    char* attribute = malloc(sizeof(char)*strlen(token.attribute.string)+1);
    strcpy(attribute, token.attribute.string);
    token.attribute.string = attribute;
    s->tokens[s->top] = token;

    return 1;
}