#ifndef IFJ20C_TOKEN_H
#define IFJ20C_TOKEN_H

#include <stdint.h>

typedef enum {
    // Meta tokens
    TT_ERR, //! Lexical analysis failed!
    TT_EOL,
    TT_EOF,

    // Keywords
    TT_KEYWORD_ELSE,
    TT_KEYWORD_FLOAT64,
    TT_KEYWORD_FOR,
    TT_KEYWORD_FUNC,
    TT_KEYWORD_IF,
    TT_KEYWORD_INT,
    TT_KEYWORD_PACKAGE,
    TT_KEYWORD_RETURN,
    TT_KEYWORD_STRING,

    // Tokens with an attribute
    TT_IDENTIFIER, //String
    TT_STRING_LITERAl, //String
    TT_INTEGER_LITERAL, //Int64
    TT_FLOATING_LITERAL, //Double

    //Assigment
    TT_ASSIGNMENT,
    TT_DECLARATION_ASSIGNMENT,

    //Math operators
    TT_PLUS,
    TT_MINUS,
    TT_ASTERISK,
    TT_SLASH,

    //Separators
    TT_COMMA,
    TT_SEMICOLON,

    //Comparison operators
    TT_EQUALS,
    TT_NOT_EQUALS,
    TT_LESS_OR_EQUALS,
    TT_GREATER_OR_EQUALS,
    TT_LESS,
    TT_GREATER,

    //Brackets
    TT_OPEN_PARENTHESES,
    TT_CLOSE_PARENTHESES,
    TT_OPEN_BRACES,
    TT_CLOSE_BRACES,

    //Precedence meta-tokens
    TT_NONTERMINAL,
    TT_SHIFT,
    TT_STOP,
} Token_type;

union Token_attribute{
    char* string;
    int64_t integer;
    double floating;
};

struct {
    Token_type token_type;
    union Token_attribute attribute;
} typedef Token;

/**
 * Converts attribute value of token into string.
 * @param token
 * @return Non owning string
 */
char* to_string_attribute(const Token* token);

#endif //IFJ20C_TOKEN_H
