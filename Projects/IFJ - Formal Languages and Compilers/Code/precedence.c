#include "precedence.h"

typedef enum{
    ADD_SUBTRACT,
    MULTIPLY_DIVIDE,
    OPEN_PARENTHESES,
    CLOSE_PARENTHESES,
    IDENTIFIER,
    COMPARISON,
    STOP_TOKEN,
} Precedence_table_index;

Precedence_table_index to_precedence_index(Token_type tokenType){
    switch (tokenType) {
        case TT_IDENTIFIER:
        case TT_NONTERMINAL:
        case TT_STRING_LITERAl:
        case TT_INTEGER_LITERAL:
        case TT_FLOATING_LITERAL:
            return IDENTIFIER;
        case TT_PLUS:
        case TT_MINUS:
            return ADD_SUBTRACT;
        case TT_ASTERISK:
        case TT_SLASH:
            return MULTIPLY_DIVIDE;
        case TT_EQUALS:
        case TT_NOT_EQUALS:
        case TT_LESS_OR_EQUALS:
        case TT_GREATER_OR_EQUALS:
        case TT_LESS:
        case TT_GREATER:
            return COMPARISON;
        case TT_OPEN_PARENTHESES:
            return OPEN_PARENTHESES;
        case TT_CLOSE_PARENTHESES:
            return CLOSE_PARENTHESES;
        default:
            return STOP_TOKEN;
    }
}

Precedence_sign precedence_lookup(Token_type stack_top, Token_type input_token){
    int top = to_precedence_index(stack_top);
    int b = to_precedence_index(input_token);
    return precedence_table[top][b];
}
