#ifndef IFJ20C_SCANNER_H
#define IFJ20C_SCANNER_H

#include "token.h"
#include "stdio.h"

/**
 * Sets file stream for lexical analysis
 * @param[IN] file
 * @return -1 when file is NULL
 */
int set_file(FILE* file);

/**
 * Starts reading source file from the beginning
 */
int rewind_file();

/**
 * Lexes next token from open file
 * @param[OUT] token
 * @return -1 on error, 1 on success, 0 on EOF
 */
int next_token(Token* token);

/**
 * @param[IN] attribute
 * @returns appropriate token_type for keywords and identifiers.
 */
Token_type get_keyword(const char* attribute);
#endif //IFJ20C_SCANNER_H
