/**
 * parser.c
 * 
 * @brief Syntax and semantic analysis. Parsing expressions.
 * 
 * @author Petr Růžanský <xruzan00>
 *         Radek Maňák <xmanak20>
 *         Adrián Bobola <xbobol00>
 * 
 */

#include "parser.h"
#include "scanner.h"
#include "token.h"
#include "return-codes.h"
#include "stdbool.h"
#include "codegen.h"
#include "symtable.h"
#include "string.h"
#include "precedence.c"
#include "symstack.h"
#include "symtablestack.h"
#include "token_stack.h"

bool is_EOL = false;
bool EOL_allowed = true;
bool second_token = false;
int return_code;
Token token;
Token prev_token;
Symtable_node_ptr global_symbol_table;
Symtable_item *current_function;
int global_temporary_variable_counter = 0;
int param_counter;
Symstack *expression_result_stack;
Symtable_stack *symtable_stack;
int control_flow_counter = 0;

tTokenStack idStack;

// Load next token, check the return code and check if EOL is allowed.
#define NEXT()                              \
    {                                       \
        is_EOL = false;                     \
        while (1)                           \
        {                                   \
            next_token(&token);             \
            if (token.token_type == TT_ERR) \
            {                               \
                return LEXICAL_ERROR;       \
            }                               \
            if (token.token_type == TT_EOL) \
            {                               \
                if (EOL_allowed)            \
                {                           \
                    is_EOL = true;          \
                    continue;               \
                }                           \
                else                        \
                {                           \
                    break;                  \
                }                           \
            }                               \
            break;                          \
        }                                   \
    }

#define NEXT_WITH_EOL()                 \
    {                                   \
        next_token(&token);             \
        if (token.token_type == TT_ERR) \
        {                               \
            return LEXICAL_ERROR;       \
        }                               \
    }

// Compare actual token with TOK and then call and compare next token.
#define CHECK_AND_LOAD_TOKEN(TOK)             \
    {                                         \
        if (second_token == true)             \
        {                                     \
            if (prev_token.token_type != TOK) \
            {                                 \
                return SYNTAX_ERROR;          \
            }                                 \
            second_token = false;             \
        }                                     \
        else                                  \
        {                                     \
            if (token.token_type != TOK)      \
            {                                 \
                return SYNTAX_ERROR;          \
            }                                 \
            NEXT();                           \
        }                                     \
    }

// Call function FUN and check return code.
#define CHECK_AND_CALL_FUNCTION(FUN) \
    {                                \
        return_code = FUN;           \
        if (return_code != OK)       \
        {                            \
            return return_code;      \
        }                            \
    }

// Init nonterminal states:
int Func_param_n();
int For_declr();
int Else();
int Id_n();
int Expresion();
int Expression_n();
int Declr();
int Types_n();
int Func_param();
int State();
int State_id();
int State_data_type();
int Types();
int Params_n();
int Param();
int Stat_list();
int Ret_types();
int Params();
int Func();
int Body();
int FirstBody();
int Preamble();
int Start();

int fast_func();
int fast_param(Symtable_item *function);
int fast_params(Symtable_item *function);
int fast_params_n(Symtable_item *function);
int fast_ret_types(Symtable_item *function);
int fast_types(Symtable_item *function);
int fast_state_data_type(Symtable_item *function);
int fast_types_n(Symtable_item *function);
/////////////////////////////

// NONTERMINAL STATES

int For_declr()
{
    switch (token.token_type)
    {
    case TT_IDENTIFIER:
        // Rule: <for_declr> -> <declr> ;
        CHECK_AND_CALL_FUNCTION(Declr());

        CHECK_AND_LOAD_TOKEN(TT_SEMICOLON);
        return OK;
        break;
    case TT_SEMICOLON:
        // Rule: <for_declr> -> ;

        CHECK_AND_LOAD_TOKEN(TT_SEMICOLON);

        return OK;
        break;
    default:
        return SYNTAX_ERROR;
        break;
    }
}
int Id_n()
{
    switch (token.token_type)
    {
    case TT_COMMA:
        // Rule: <id_n> -> , id <id_n>

        CHECK_AND_LOAD_TOKEN(TT_COMMA);

        if (token.token_type == TT_IDENTIFIER)
        {
            tokenStackPush(&idStack, token);
        }
        CHECK_AND_LOAD_TOKEN(TT_IDENTIFIER);

        CHECK_AND_CALL_FUNCTION(Id_n());

        return OK;
    case TT_ASSIGNMENT:
    case TT_DECLARATION_ASSIGNMENT:
    case TT_OPEN_PARENTHESES:
        // Rule: <id_n> -> eps

        return OK;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Else()
{
    switch (token.token_type)
    {
        // case TT_IDENTIFIER:
        // case TT_CLOSE_BRACES:
        // case TT_KEYWORD_IF:
        // case TT_KEYWORD_FOR:
        // case TT_KEYWORD_RETURN:

        //     // Rule: <else> -> eps
        //     return OK;
        //     break;

    case TT_KEYWORD_ELSE:
        // Rule: <else> -> else { <stat_list> }

        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_ELSE);

        CHECK_AND_LOAD_TOKEN(TT_OPEN_BRACES);
        Symtable_node_ptr localtab_else = NULL;
        Symtable_init(&localtab_else);
        Symtable_stack_insert(symtable_stack, localtab_else);

        if (is_EOL)
        {
            is_EOL = false;
        }
        else
        {
            return SYNTAX_ERROR;
        }

        CHECK_AND_CALL_FUNCTION(Stat_list());

        CHECK_AND_LOAD_TOKEN(TT_CLOSE_BRACES);
        Symtable_node_ptr helper = Symtable_stack_pop(symtable_stack);
        Symtable_dispose(&helper);

        return OK;
        break;

    default:
        return SYNTAX_ERROR;

        break;
    }
}

Symtable_item *create_shift()
{
    Symtable_item *shift = create_item();
    shift->token.token_type = TT_SHIFT;
    return shift;
}

Symtable_item *find_terminal_top(Symstack *symstack)
{
    for (int i = symstack->top; i >= 0; i--)
    {
        Symtable_item *item = *(symstack->stack + i);
        switch (item->token.token_type)
        {
        case TT_SHIFT:
        case TT_NONTERMINAL:
            break;
        default:
            return item;
        }
    }
    return NULL;
}

void insert_shift(Symstack *symstack, Symtable_item *item)
{
    Symstack *temp_stack;
    Symstack_init(&temp_stack);
    for (int i = symstack->top; i >= 0; i--)
    {
        Symtable_item *current_item = *(symstack->stack + i);
        if (current_item == item)
        {
            Symstack_insert(symstack, create_shift());
            break;
        }
        else
        {
            Symstack_insert(temp_stack, Symstack_pop(symstack));
        }
    }
    while (!Symstack_empty(temp_stack))
    {
        Symstack_insert(symstack, Symstack_pop(temp_stack));
    }
    Symstack_dispose(&temp_stack);
}

int shift_position(Symstack *symstack)
{
    for (int i = symstack->top; i > 0; i--)
    {
        Symtable_item *current_item = *(symstack->stack + i);
        if (current_item->token.token_type != TT_SHIFT)
        {
            continue;
        }
        return i;
    }
    return -1;
}

bool is_compare_operator(Token_type operator)
{
    switch (operator)
    {
    case TT_LESS:
    case TT_LESS_OR_EQUALS:
    case TT_EQUALS:
    case TT_NOT_EQUALS:
    case TT_GREATER:
    case TT_GREATER_OR_EQUALS:
        return true;
    default:
        return false;
    }
}

int parse_expression_binary_operation(Symstack *symstack, int operator_pos)
{
    if (symstack->top != operator_pos + 1)
    {
        return SYNTAX_ERROR;
    }
    Symtable_item *right_item = Symstack_pop(symstack);
    Symtable_item *operator_item = Symstack_pop(symstack);
    Symtable_item *left_item = Symstack_pop(symstack);
    Symtable_item *shift = Symstack_pop(symstack);

    char *nonterminal_identifier = malloc(sizeof(char) * 20);
    sprintf(nonterminal_identifier, "expr-var%d", global_temporary_variable_counter++);
    generate_declaration("LF@", nonterminal_identifier);
    if (left_item->dataType[0] != right_item->dataType[0])
    {
        fprintf(stderr, "%s does not have the same type as %s\n",
                left_item->token.attribute.string, right_item->token.attribute.string);
        return SEMANTIC_ERROR_TYPE_COMPATIBILITY;
    }
    int unsupported_operation = 1;
    switch (left_item->dataType[0])
    {
    case DT_VOID:
        break;
    case DT_STRING:
        unsupported_operation = generate_arithmetic_operation_string(operator_item->token.token_type, nonterminal_identifier,
                                                                     left_item->token.attribute.string,
                                                                     right_item->token.attribute.string);
        break;
    case DT_INT:
        if (operator_item->token.token_type == TT_SLASH && right_item->dataType[1] == DT_INT){
            return SEMANTIC_ERROR_ZERO_DIV; // Very hacky way to detect zero division
        }
        unsupported_operation = generate_arithmetic_operation_int(operator_item->token.token_type, nonterminal_identifier,
                                                                  left_item->token.attribute.string,
                                                                  right_item->token.attribute.string);
        break;
    case DT_FLOAT:
        if (operator_item->token.token_type == TT_SLASH && right_item->dataType[1] == DT_INT){
            return SEMANTIC_ERROR_ZERO_DIV; // Very hacky way to detect zero division
        }
        unsupported_operation = generate_arithmetic_operation_float(operator_item->token.token_type, nonterminal_identifier,
                                                                    left_item->token.attribute.string,
                                                                    right_item->token.attribute.string);
        break;
    case DT_BOOL:
        break;
    }
    if (unsupported_operation)
    {
        return SEMANTIC_ERROR_TYPE_COMPATIBILITY;
    }
    if (is_compare_operator(operator_item->token.token_type))
    {
        left_item->dataType[0] = DT_BOOL;
    }
    free(left_item->token.attribute.string);
    left_item->token.attribute.string = nonterminal_identifier;

    if (shift->token.token_type != TT_SHIFT)
    {
        return INTERNAL_ERROR;
    }
    free_symtable_item(shift);
    Symstack_insert(symstack, left_item);
    return OK;
}

int convert_int_to_literal(char *out, int64_t integer)
{
    sprintf(out, "int@%ld", integer);
    return 0;
}

int convert_double_to_literal(char *out, double double_num)
{
    sprintf(out, "float@%a", double_num);
    return 0;
}

int convert_string_to_literal(char *out, const char *string, size_t length)
{
    size_t out_max_length = length * 1.5;
    sprintf(out, "string@");
    int out_position = 7; //set position after prefix
    for (int i = 0; i < length; i++)
    {
        if (out_position + 5 > out_max_length)
        { // If there is chance to not fit allocate more space
            out_max_length = out_max_length * 1.2;
            if (out_max_length < 10)
            { // At least 10 chars minimum for small string edge cases
                out_max_length = 10;
            }
            if (realloc(out, out_max_length) == NULL)
            {
                return -1;
            }
        }
        char ch = string[i];
        if (ch >= 0 && ch <= 32 || ch == 35 || ch == 92)
        {
            char escape_sequence[5];
            sprintf(escape_sequence, "\\%.3d", ch);
            out[out_position++] = escape_sequence[0];
            out[out_position++] = escape_sequence[1];
            out[out_position++] = escape_sequence[2];
            out[out_position++] = escape_sequence[3];
        }
        else
        {
            out[out_position] = ch;
            out_position++;
        }
    }
    out[out_position] = 0; //ending null byte
    return 0;
}

int parse_literal(Symstack *symstack)
{
    Symtable_item *literal = Symstack_pop(symstack);
    Symtable_item *shift = Symstack_pop(symstack);

    char *nonterminal_identifier = malloc(sizeof(char) * 20);
    sprintf(nonterminal_identifier, "expr-var%d", global_temporary_variable_counter++);
    generate_declaration("LF@", nonterminal_identifier);

    char *value_literal;
    switch (literal->token.token_type)
    {
    case TT_FLOATING_LITERAL:
        literal->dataType[0] = DT_FLOAT;
        value_literal = malloc(sizeof(char) * 150);
        convert_double_to_literal(value_literal, literal->token.attribute.floating);
        if (literal->token.attribute.floating == 0.0){ // Very hacky way to mark this variable as holding zero
            literal->dataType[1] = DT_INT;
        }
        generate_move("LF@", nonterminal_identifier, "", value_literal);
        break;
    case TT_STRING_LITERAl:
        literal->dataType[0] = DT_STRING;
        size_t length = strlen(literal->token.attribute.string);
        value_literal = malloc(sizeof(char) * (size_t)(length * 1.5));
        convert_string_to_literal(value_literal, literal->token.attribute.string, length);
        generate_move("LF@", nonterminal_identifier, "", value_literal);
        break;
    case TT_INTEGER_LITERAL:
        literal->dataType[0] = DT_INT;
        value_literal = malloc(sizeof(char) * 150);
        convert_int_to_literal(value_literal, literal->token.attribute.integer);
        if (literal->token.attribute.floating == 0){ // Very hacky way to mark this variable as holding zero
            literal->dataType[1] = DT_INT;
        }
        generate_move("LF@", nonterminal_identifier, "", value_literal);
        break;
    default:
        return SYNTAX_ERROR;
    }
    literal->token.token_type = TT_NONTERMINAL;
    literal->token.attribute.string = nonterminal_identifier;

    free(value_literal);
    free_symtable_item(shift);
    Symstack_insert(symstack, literal);
    return OK;
}

int parse_expression_parentheses(Symstack *symstack)
{
    Symtable_item *right_parentheses = Symstack_pop(symstack);
    Symtable_item *nonterminal = Symstack_pop(symstack);
    Symtable_item *left_parentheses = Symstack_pop(symstack);
    Symtable_item *shift = Symstack_pop(symstack);

    free_symtable_item(right_parentheses);
    free_symtable_item(left_parentheses);
    free_symtable_item(shift);
    Symstack_insert(symstack, nonterminal);
    return OK;
}

int parse_expression_id(Symstack *symstack)
{
    Symtable_item *identifier = Symstack_pop(symstack);
    Symtable_item *shift = Symstack_pop(symstack);
    identifier->token.token_type = TT_NONTERMINAL;

    if (strcmp(identifier->token.attribute.string, "_") == 0){
        fprintf(stderr, "Error attempting to read from _");
        return SEMANTIC_ERROR_OTHERS;
    }

    char *local_name =
        malloc(sizeof(char) * strlen(identifier->token.attribute.string) + 1);
    strcpy(local_name, identifier->token.attribute.string);
    Symtable_item *variable = Symtable_stack_lookup(symtable_stack, local_name);
    if (variable == NULL)
    {
        return SEMANTIC_ERROR_UNDEFINED_VARIABLE;
    }
    identifier->dataType[0] = variable->dataType[0];

    free_symtable_item(shift);
    Symstack_insert(symstack, identifier);
    return OK;
}

int parse_expresion_rule(Symstack *symstack, int shift_pos)
{
    int current_pos = shift_pos + 1;
    if (current_pos > symstack->top)
    {
        return SYNTAX_ERROR;
    }
    switch ((*(symstack->stack + current_pos))->token.token_type)
    {
    case TT_NONTERMINAL:
        current_pos++;
        if (current_pos > symstack->top)
        {
            return SYNTAX_ERROR;
        }
        switch ((*(symstack->stack + current_pos))->token.token_type)
        {
        case TT_PLUS:
            //E -> E+E
            return parse_expression_binary_operation(symstack, current_pos);
        case TT_MINUS:
            //E -> E-E
            return parse_expression_binary_operation(symstack, current_pos);
        case TT_ASTERISK:
            //E -> E*E
            return parse_expression_binary_operation(symstack, current_pos);
        case TT_SLASH:
            //E -> E/E
            return parse_expression_binary_operation(symstack, current_pos);
        case TT_LESS:
        case TT_LESS_OR_EQUALS:
        case TT_GREATER:
        case TT_GREATER_OR_EQUALS:
        case TT_NOT_EQUALS:
        case TT_EQUALS:
            // E -> E compare E
            return parse_expression_binary_operation(symstack, current_pos);
        default:
            return SYNTAX_ERROR;
        }
    case TT_OPEN_PARENTHESES:
        //E -> (E)
        return parse_expression_parentheses(symstack);
    case TT_INTEGER_LITERAL:
    case TT_STRING_LITERAl:
    case TT_FLOATING_LITERAL:
        return parse_literal(symstack);
    case TT_IDENTIFIER:
        // E -> id+
        return parse_expression_id(symstack);
        // MAYBE FUNEXP?
        break;
    default:
        return SYNTAX_ERROR;
    }
    return SYNTAX_ERROR;
}

bool is_precedence_end(Token_type tokenType)
{
    switch (tokenType)
    {
    case TT_OPEN_PARENTHESES:
    case TT_CLOSE_PARENTHESES:
    case TT_IDENTIFIER:
    case TT_STRING_LITERAl:
    case TT_INTEGER_LITERAL:
    case TT_FLOATING_LITERAL:
    case TT_PLUS:
    case TT_MINUS:
    case TT_ASTERISK:
    case TT_SLASH:
    case TT_SEMICOLON:
    case TT_EQUALS:
    case TT_NOT_EQUALS:
    case TT_LESS_OR_EQUALS:
    case TT_GREATER_OR_EQUALS:
    case TT_LESS:
    case TT_GREATER:
        return false;
    default:
        return true;
    }
}

int Expresion()
{
    Symstack *symstack;
    Symstack_init(&symstack);
    Symtable_item *stop = create_item();
    stop->token.token_type = TT_STOP;
    Symstack_insert(symstack, stop);
    int shift_pos;
    int parentheses_depth = 0;

    bool end_found = false;
    Symtable_item *a, *b;
    do
    {
        a = find_terminal_top(symstack);
        b = create_item();
        if (is_precedence_end(token.token_type) || parentheses_depth == 0 && token.token_type == TT_CLOSE_PARENTHESES)
        {
            b->token.token_type = TT_STOP;
            end_found = true;
        }
        else
        {
            b->token.token_type = token.token_type;
            b->token.attribute = token.attribute;
        }
        switch (precedence_lookup(a->token.token_type, b->token.token_type))
        {
        case PRECEDENCE_E:
            Symstack_insert(symstack, b);
            if (token.token_type == TT_OPEN_PARENTHESES)
            {
                parentheses_depth++;
            }
            else if (token.token_type == TT_CLOSE_PARENTHESES)
            {
                parentheses_depth--;
            }
            if (!end_found)
            {
                NEXT_WITH_EOL()
            }
            break;
        case PRECEDENCE_L:
            insert_shift(symstack, a);
            Symstack_insert(symstack, b);
            if (token.token_type == TT_OPEN_PARENTHESES)
            {
                parentheses_depth++;
            }
            else if (token.token_type == TT_CLOSE_PARENTHESES)
            {
                parentheses_depth--;
            }
            if (!end_found)
            {
                NEXT_WITH_EOL()
            }
            break;
        case PRECEDENCE_G:
            shift_pos = shift_position(symstack);
            if (shift_pos != -1)
            {
                CHECK_AND_CALL_FUNCTION(parse_expresion_rule(symstack, shift_pos));
            }
            else
            {
                return SYNTAX_ERROR;
            }
            free_symtable_item(b);
            break;
        case PRECEDENCE_X:
            return SYNTAX_ERROR;
        }
    } while (!(end_found && find_terminal_top(symstack)->token.token_type == TT_STOP));

    // Move result to known variable
    Symtable_item *result = Symstack_pop(symstack);
    Symstack_insert(expression_result_stack, result);

    Symstack_dispose(&symstack);
    return OK;
}

int Expression_n()
{
    switch (token.token_type)
    {
    case TT_CLOSE_BRACES:
    case TT_EOL:
        // Rule: <Expression_n> -> eps
        return OK;
    case TT_COMMA:
        // Rule: <Expression_n> -> , <Expression> <Expression_n>
        CHECK_AND_LOAD_TOKEN(TT_COMMA)
        CHECK_AND_CALL_FUNCTION(Expresion())
        CHECK_AND_CALL_FUNCTION(Expression_n())
        break;
    default:
        return SYNTAX_ERROR;
    }

    return OK;
}

int function_call(Symtable_item *function)
{
    generate_frame();
    if (strcmp(function->token.attribute.string, "print") == 0)
    {
        // print takes arguments from stack
        char arg_count[10];
        sprintf(arg_count, "%d", expression_result_stack->top + 1);
        generate_declaration("TF@", "%1");
        generate_move("TF@", "%1", "int@", arg_count);
        for (int i = expression_result_stack->top; i >= 0; i--)
        {
            generate_push("LF@", expression_result_stack->stack[i]->token.attribute.string);
        }
    }
    else
    {
        if (function->parameter_count != expression_result_stack->top+1){
            fprintf(stderr, "Function called with wrong number of parameters");
            return SEMANTIC_ERROR_FUNCTION;
        }
        for (int i = 0; i <= expression_result_stack->top; ++i)
        {
            if (expression_result_stack->stack[i]->dataType[i] != function->parameters[i].dataType){
                fprintf(stderr, "Incorrect datatype of parameter number %d while calling function %s\n", i+1, function->token.attribute.string);
                return SEMANTIC_ERROR_FUNCTION;
            }
            char argument[10];
            sprintf(argument, "%%%d", i + 1);
            generate_declaration("TF@", argument);
            generate_move("TF@", argument, "LF@", expression_result_stack->stack[i]->token.attribute.string);
        }
    }
    Symstack_dispose(&expression_result_stack);
    Symstack_init(&expression_result_stack);
    generate_function_call(function->token.attribute.string);
    // Create objecct with called function name and store in expression result
    Symtable_item* function_result = create_item_copy(function);
    Symstack_insert(expression_result_stack, function_result);
    return OK;
}

int function_call_return(Symtable_item* function, bool declaration_forbidden, int starting_id) {
    if (function == NULL){
        return SEMANTIC_ERROR_FUNCTION;
    }
    int param_pos = 0;
    for (int i = starting_id; i < function->return_values_count; i++, param_pos++) {
        if (i > idStack.top){
            fprintf(stderr, "Left side of assignment has %d value but function returns %d\n",
                    idStack.top+1, function->return_values_count);
            return SEMANTIC_ERROR_FUNCTION;
        }
        Symtable_item *identifier = Symtable_search(*Symtable_stack_head(symtable_stack), idStack.tokens[i].attribute.string);
        if (strcmp(idStack.tokens[i].attribute.string, "_") == 0){
            continue;
        }
        if (declaration_forbidden) {
            // Assignment
            if (identifier == NULL){
                return SEMANTIC_ERROR_UNDEFINED_VARIABLE;
            }
        } else {
            //Declaration
            if (identifier != NULL){
                return SEMANTIC_ERROR_UNDEFINED_VARIABLE;
            }
            generate_declaration("LF@", idStack.tokens[i].attribute.string);
            identifier = create_item();
            identifier->token.token_type = TT_IDENTIFIER;
            identifier->dataType[0] = function->dataType[param_pos];
            identifier->token.attribute.string = malloc(
                    sizeof(char) * strlen(idStack.tokens[i].attribute.string) + 1);
            strcpy(identifier->token.attribute.string, idStack.tokens[i].attribute.string);
            Symtable_insert(Symtable_stack_head(symtable_stack), identifier->token.attribute.string, identifier);
        }
        char argument[10];
        sprintf(argument, "%d", i + 1);
        if (identifier->dataType[0] != function->dataType[param_pos]){
            fprintf(stderr, "Function parameter %s of function %s does not have the same datatype as identifier %s\n",
                    function->parameters[param_pos].identifier, function->token.attribute.string,
                    idStack.tokens[i].attribute.string);
            return SEMANTIC_ERROR_DATA_TYPE;
        }
        generate_move("LF@", idStack.tokens[i].attribute.string, "TF@%retval", argument);
    }
    return OK;
}

int expression_or_function_call()
{
    if (token.token_type == TT_IDENTIFIER)
    {
        Symtable_item *function = Symtable_search(global_symbol_table, token.attribute.string);
        if (function != NULL)
        {
            // Is function. Call move parameters to temporary frame and call it.
            CHECK_AND_LOAD_TOKEN(TT_IDENTIFIER);
            CHECK_AND_LOAD_TOKEN(TT_OPEN_PARENTHESES)
            CHECK_AND_CALL_FUNCTION(Func_param())
            // Fills expression_result_stack with parameter variables
            CHECK_AND_LOAD_TOKEN(TT_CLOSE_PARENTHESES);
            CHECK_AND_CALL_FUNCTION(function_call(function));
        }
        else
        {
            // Variable not a function
            CHECK_AND_CALL_FUNCTION(Expresion())
        }
    }
    else
    {
        // Likely a literal value or error
        CHECK_AND_CALL_FUNCTION(Expresion())
    }

    if (token.token_type == TT_EOL)
    {
        // EOL token ends expression
        NEXT()
        is_EOL = true;
    }
    if (!is_EOL)
    {
        CHECK_AND_CALL_FUNCTION(Expression_n())
    }
    return OK;
}

int move_return_values_from_function(bool declaration_forbidden){
    int rvalue_counter = 0;
    for (int id_counter = 0; id_counter <= idStack.top || rvalue_counter <= expression_result_stack->top; ++id_counter, ++rvalue_counter) {
        if (id_counter > idStack.top ||  rvalue_counter > expression_result_stack->top){
            fprintf(stderr, "Number of values on left side of an assignment does not match number of values on right side");
            return SEMANTIC_ERROR_OTHERS;
        }
        if (expression_result_stack->stack[rvalue_counter]->isfunction){
            // Obtain full global function item from "reference"
            Symtable_item *called_function = Symtable_search(global_symbol_table, expression_result_stack->stack[id_counter]->token.attribute.string);
            CHECK_AND_CALL_FUNCTION(function_call_return(called_function, declaration_forbidden, id_counter))
            id_counter += called_function->return_values_count-1;
        } else {
            if (strcmp(idStack.tokens[id_counter].attribute.string, "_") == 0){
                continue;
            }
            Symtable_item* identifier = Symtable_stack_lookup(symtable_stack, idStack.tokens[id_counter].attribute.string);
            if (identifier == NULL){
                if (declaration_forbidden){
                    return SEMANTIC_ERROR_UNDEFINED_VARIABLE;
                }
                generate_declaration("LF@", idStack.tokens[id_counter].attribute.string);
                identifier = create_item();
                identifier->token.token_type = TT_IDENTIFIER;
                identifier->token.attribute.string = malloc(sizeof(char)*strlen(idStack.tokens[id_counter].attribute.string) + 1);
                identifier->dataType[0] = expression_result_stack->stack[id_counter]->dataType[0];
                strcpy(identifier->token.attribute.string, idStack.tokens[id_counter].attribute.string);
                Symtable_insert(Symtable_stack_head(symtable_stack), identifier->token.attribute.string, identifier);
            }
            generate_move("LF@", idStack.tokens[id_counter].attribute.string, "LF@", expression_result_stack->stack[id_counter]->token.attribute.string);
        }
    }

    if (token.token_type == TT_EOL){
        NEXT()
        is_EOL = true;
    }
    while (!tokenStackEmpty(&idStack))
    {
        tokenStackPop(&idStack);
    }
    Symstack_dispose(&expression_result_stack);
    Symstack_init(&expression_result_stack);
    return OK;
}

int Declr()
{
    // Rule: <declr> -> := <expr>
    CHECK_AND_LOAD_TOKEN(TT_DECLARATION_ASSIGNMENT)

    CHECK_AND_CALL_FUNCTION(expression_or_function_call());

    CHECK_AND_CALL_FUNCTION(move_return_values_from_function(false))

    return OK;
}

int Types_n()
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:
        // Rule: <types_n> -> eps
        return OK;
        break;

    case TT_COMMA:
        // Rule: <types_n> -> , <data_type> <types_n>
        CHECK_AND_LOAD_TOKEN(TT_COMMA);

        CHECK_AND_CALL_FUNCTION(State_data_type());

        CHECK_AND_CALL_FUNCTION(Types_n());
        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Func_param_n()
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:

        // Rule: <Func_param_n> -> eps

        return OK;
        break;

    case TT_COMMA:
        // Rule: <Func_param> -> , <expression> <func_param_n>

        CHECK_AND_LOAD_TOKEN(TT_COMMA);
        CHECK_AND_CALL_FUNCTION(Expresion());
        CHECK_AND_CALL_FUNCTION(Func_param_n());
        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Func_param()
{
    switch (token.token_type)
    {
    case TT_IDENTIFIER:
    case TT_OPEN_PARENTHESES:
    case TT_PLUS:
    case TT_MINUS:
    case TT_ASTERISK:
    case TT_SLASH:
    case TT_INTEGER_LITERAL:
    case TT_STRING_LITERAl:
    case TT_FLOATING_LITERAL:

        // Rule: <Func_param> -> <expr> <func_param_n>

        CHECK_AND_CALL_FUNCTION(Expresion());
        CHECK_AND_CALL_FUNCTION(Func_param_n());
        return OK;
        break;

    case TT_CLOSE_PARENTHESES:
        // Rule: <Func_param> -> eps
        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int State()
{
    Symtable_node_ptr localtab_if_for = NULL;
    Symtable_init(&localtab_if_for);
    Symtable_node_ptr stack_pop_helper = NULL;
    switch (token.token_type)
    {
    case TT_IDENTIFIER:
        // Rule: <state> -> id <state_id>
        tokenStackPush(&idStack, token);
        NEXT()
        CHECK_AND_CALL_FUNCTION(State_id())
        break;

    case TT_KEYWORD_IF:
        // Rule: <state> -> if <expr> { <stat_list> } <else>

        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_IF);

        CHECK_AND_CALL_FUNCTION(Expresion())
        int if_number = ++control_flow_counter;
        Symtable_item *expression_result = Symstack_pop(expression_result_stack);
        if (expression_result->dataType[0] != DT_BOOL)
        {
            fprintf(stderr, "If did not get expression result of type bool\n");
            return SEMANTIC_ERROR_TYPE_COMPATIBILITY;
        }
        char *expresion_result = expression_result->token.attribute.string;
        generate_if_head(expresion_result, if_number);

        CHECK_AND_LOAD_TOKEN(TT_OPEN_BRACES);
        Symtable_stack_insert(symtable_stack, localtab_if_for);

        if (is_EOL)
        {
            is_EOL = false;
        }
        else
        {
            return SYNTAX_ERROR;
        }

        CHECK_AND_CALL_FUNCTION(Stat_list());

        CHECK_AND_LOAD_TOKEN(TT_CLOSE_BRACES);
        generate_if_middle(if_number);
        stack_pop_helper = Symtable_stack_pop(symtable_stack);
        Symtable_dispose(&stack_pop_helper); // Pop true frame
        CHECK_AND_CALL_FUNCTION(Else());
        generate_if_end(if_number);
        free_symtable_item(expression_result);

        return OK;
        break;

    case TT_KEYWORD_FOR:
        // Rule: <state> -> for <for_declr> <expr> ; <expr> { <stat_list> }
        fprintf(stderr, "For loop is not supported!");
        return SYNTAX_ERROR;
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_FOR);

        CHECK_AND_CALL_FUNCTION(For_declr());

        CHECK_AND_CALL_FUNCTION(Expresion());
        Symtable_item *helper_for_expr1 = Symstack_pop(expression_result_stack);
        char *expresion1_result_for = helper_for_expr1->token.attribute.string;
        //generate_for_head(expresion1_result_for, local_counter_for);

        CHECK_AND_LOAD_TOKEN(TT_SEMICOLON);

        CHECK_AND_CALL_FUNCTION(Expresion());
        Symtable_item *helper_for_expr2 = Symstack_pop(expression_result_stack);
        char *expresion2_result_for = helper_for_expr2->token.attribute.string;

        CHECK_AND_LOAD_TOKEN(TT_OPEN_BRACES);
        Symtable_stack_insert(symtable_stack, localtab_if_for);
        //generate_for_label_cycle(local_counter_for); //label CYCLE

        CHECK_AND_CALL_FUNCTION(Stat_list());

        //generate_for_iterate(expresion2_result_for, local_counter_for);
        //generate_for_label_end(for_counter);
        CHECK_AND_LOAD_TOKEN(TT_CLOSE_BRACES);
        stack_pop_helper = Symtable_stack_pop(symtable_stack);
        Symtable_dispose(&stack_pop_helper);
        return OK;
        break;

    case TT_KEYWORD_RETURN:
        // Rule: <state> -> return <expr>
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_RETURN);
        // Rule: <state> -> return eps
        if (!is_EOL)
        {
            CHECK_AND_CALL_FUNCTION(Expresion())

            CHECK_AND_CALL_FUNCTION(Expression_n())
        }
        if (!is_EOL)
        {
            if (token.token_type == TT_EOL)
            {
                NEXT()
                is_EOL = true;
            }
            else
            {
                return SYNTAX_ERROR;
            }
        }

        if (current_function->return_values_count != expression_result_stack->top + 1)
        {
            fprintf(stderr, "Semantic error in function %s: Expected %d return values but found %d values instead\n",
                    current_function->token.attribute.string, current_function->return_values_count,
                    expression_result_stack->top + 1);
            return SEMANTIC_ERROR_FUNCTION;
        }
        for (int i = 0; i < current_function->return_values_count; i++)
        {
            if (expression_result_stack->stack[i]->dataType[0] != current_function->dataType[i])
            {
                fprintf(stderr, "Semantic error in function %s: Return variable datatype does not match!\n",
                        current_function->token.attribute.string);
                return SEMANTIC_ERROR_FUNCTION;
            }
            generate_return_move(expression_result_stack->stack[i]->token.attribute.string, i + 1);
        }
        Symstack_dispose(&expression_result_stack);
        Symstack_init(&expression_result_stack);

        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
    return OK;
}

int State_id()
{
    CHECK_AND_CALL_FUNCTION(Id_n())
    if (token.token_type == TT_DECLARATION_ASSIGNMENT)
    {
        // Rule: <state_id> -> <Id_n> := <declr>

        CHECK_AND_CALL_FUNCTION(Declr())
        return OK;
    }
    else if (token.token_type == TT_ASSIGNMENT)
    {
        // Rule: <state_id> -> <Id_n> = <expr>

        CHECK_AND_LOAD_TOKEN(TT_ASSIGNMENT)
        CHECK_AND_CALL_FUNCTION(expression_or_function_call());
        CHECK_AND_CALL_FUNCTION(move_return_values_from_function(true))

        return OK;
    }
    else if (token.token_type == TT_OPEN_PARENTHESES)
    {
        // Rule: <state_id> -> ( <func_param> )
        if (idStack.top != 0)
        {
            return SYNTAX_ERROR;
            // Function call in lvalue
            // eg: id, call() :=
        }
        CHECK_AND_LOAD_TOKEN(TT_OPEN_PARENTHESES)
        CHECK_AND_CALL_FUNCTION(Func_param())
        CHECK_AND_LOAD_TOKEN(TT_CLOSE_PARENTHESES)
        Token id_token;
        tokenStackTop(&idStack, &id_token);
        tokenStackPop(&idStack);
        Symtable_item *function = Symtable_search(global_symbol_table, id_token.attribute.string);
        CHECK_AND_CALL_FUNCTION(function_call(function));

        while (!tokenStackEmpty(&idStack))
        {
            tokenStackPop(&idStack);
        }
        Symstack_dispose(&expression_result_stack);
        Symstack_init(&expression_result_stack);

        return OK;
    }

    return SYNTAX_ERROR;
}

int State_data_type()
{
    switch (token.token_type)
    {
    case TT_KEYWORD_INT:
        // Rule: <data_type> -> int
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_INT);
        return OK;
        break;

    case TT_KEYWORD_STRING:
        // Rule: <data_type> -> string
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_STRING);
        return OK;
        break;

    case TT_KEYWORD_FLOAT64:
        // Rule: <data_type> -> float
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_FLOAT64);
        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Types()
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:
        // Rule: <types> -> eps

        return OK;
        break;

    case TT_KEYWORD_INT:
    case TT_KEYWORD_STRING:
    case TT_KEYWORD_FLOAT64:
        // Rule: <types> -> <data_type> <types_n>

        CHECK_AND_CALL_FUNCTION(State_data_type());
        CHECK_AND_CALL_FUNCTION(Types_n());
        return OK;
        break;

    default:

        return SYNTAX_ERROR;
        break;
    }
}

int Params_n()
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:
        // Rule: <params_n> -> eps
        return OK;
        break;

    case TT_COMMA:
        // Rule: <params_n> -> , <param> <params_n>
        CHECK_AND_LOAD_TOKEN(TT_COMMA);

        CHECK_AND_CALL_FUNCTION(Param());

        CHECK_AND_CALL_FUNCTION(Params_n());
        return OK;
        break;
    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Param()
{
    // Rule: <param> -> id <data_type>
    CHECK_AND_LOAD_TOKEN(TT_IDENTIFIER);

    CHECK_AND_CALL_FUNCTION(State_data_type());
    generate_func_param(current_function->parameters[param_counter].identifier, param_counter + 1);
    param_counter++;

    return OK;
}

int Stat_list()
{

    switch (token.token_type)
    {
    case TT_IDENTIFIER:
    case TT_KEYWORD_IF:
    case TT_KEYWORD_FOR:
    case TT_KEYWORD_RETURN:
        // Rule: <statl> -> <state> <stat_list>
        CHECK_AND_CALL_FUNCTION(State());

        if (is_EOL != true)
        {
            return SYNTAX_ERROR;
        }
        else
        {
            is_EOL = false;
        }

        CHECK_AND_CALL_FUNCTION(Stat_list());
        return OK;
    case TT_CLOSE_BRACES:
        // Rule: <statl> -> eps

        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Ret_types()
{
    switch (token.token_type)
    {
    case TT_OPEN_PARENTHESES:
        // Rule: <ret_types> -> ( <types> )

        CHECK_AND_LOAD_TOKEN(TT_OPEN_PARENTHESES);

        CHECK_AND_CALL_FUNCTION(Types());

        CHECK_AND_LOAD_TOKEN(TT_CLOSE_PARENTHESES);

        return OK;
        break;

    case TT_OPEN_BRACES:
        // Rule: <ret_types> -> eps
        return OK;
        break;

    case TT_KEYWORD_INT:
    case TT_KEYWORD_STRING:
    case TT_KEYWORD_FLOAT64:
        // Rule: <ret_types> -> <data_type>
        CHECK_AND_CALL_FUNCTION(State_data_type());

        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Params()
{
    switch (token.token_type)
    {
    case TT_IDENTIFIER:
        // Rule: <params> -> <param> <params_n>

        CHECK_AND_CALL_FUNCTION(Param());

        CHECK_AND_CALL_FUNCTION(Params_n());

        return OK;

        break;

    case TT_CLOSE_PARENTHESES:
        // Rule: <params> -> eps

        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Func()
{
    // Rule: <func> -> func id ( <params> ) <ret_types> { <stat_list> }
    EOL_allowed = false;

    CHECK_AND_LOAD_TOKEN(TT_KEYWORD_FUNC);

    // Create function scope
    Symtable_node_ptr func;
    Symtable_init(&func);
    Symtable_stack_insert(symtable_stack, func);

    char *function_identifier;
    if (token.token_type == TT_IDENTIFIER)
    {
        function_identifier = malloc(sizeof(*token.attribute.string) * strlen(token.attribute.string) + 1);
        current_function = Symtable_search(global_symbol_table, token.attribute.string);
        strcpy(function_identifier, token.attribute.string);
        generate_func_top(token.attribute.string);
        generate_return_values(current_function);
    }
    else
    {
        return SYNTAX_ERROR;
    }
    NEXT()

    CHECK_AND_LOAD_TOKEN(TT_OPEN_PARENTHESES);

    param_counter = 0;

    CHECK_AND_CALL_FUNCTION(Params());

    // Fill function scope with parameters
    for (int i = 0; i < current_function->parameter_count; ++i)
    {
        Symtable_item *param = create_item();
        param->token.token_type = TT_IDENTIFIER;
        param->dataType[0] = current_function->parameters[i].dataType;
        param->token.attribute.string = malloc(sizeof(char) * (strlen(current_function->parameters[i].identifier) + 1));
        strcpy(param->token.attribute.string, current_function->parameters[i].identifier);
        Symtable_node_ptr *head = Symtable_stack_head(symtable_stack);
        Symtable_insert(head, param->token.attribute.string, param);
    }

    CHECK_AND_LOAD_TOKEN(TT_CLOSE_PARENTHESES);

    CHECK_AND_CALL_FUNCTION(Ret_types());

    EOL_allowed = true;

    CHECK_AND_LOAD_TOKEN(TT_OPEN_BRACES);

    if (is_EOL != true)
    {
        return SYNTAX_ERROR;
    }
    else
    {
        is_EOL = false;
    }

    CHECK_AND_CALL_FUNCTION(Stat_list());

    CHECK_AND_LOAD_TOKEN(TT_CLOSE_BRACES);
    generate_func_bottom(function_identifier);
    free(function_identifier);

    Symtable_node_ptr helper = Symtable_stack_pop(symtable_stack);
    Symtable_dispose(&helper);

    return OK;
}

int FirstBody()
{
    switch (token.token_type)
    {
    case TT_KEYWORD_FUNC:
        // Rule: <first_body> -> <func> <body>
        CHECK_AND_CALL_FUNCTION(Func());

        CHECK_AND_CALL_FUNCTION(Body())
        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Body()
{
    switch (token.token_type)
    {
    case TT_EOF:
        // Rule: <body> -> EOF
        return OK;
        break;

    case TT_KEYWORD_FUNC:
        // Rule: <body> -> <func> <body>
        CHECK_AND_CALL_FUNCTION(Func());

        CHECK_AND_CALL_FUNCTION(Body())
        return OK;
        break;

    default:
        return SYNTAX_ERROR;
        break;
    }
}

int Preamble()
{
    // rule <preamble> -> package id
    EOL_allowed = false;

    CHECK_AND_LOAD_TOKEN(TT_KEYWORD_PACKAGE);

    EOL_allowed = true;

    if (token.token_type == TT_IDENTIFIER)
    {
        char *package_id_name = "main";
        if (strcmp(token.attribute.string, package_id_name) != 0)
        {
            return SEMANTIC_ERROR_OTHERS;
        }
    }
    else
    {
        return SYNTAX_ERROR;
    }
    NEXT()

    if (is_EOL != true)
    {
        return SYNTAX_ERROR;
    }
    else
    {
        is_EOL = false;
    }

    return OK;
}

int Start()
{
    // rule <start> -> <preamle> <body>

    CHECK_AND_CALL_FUNCTION(Preamble());
    generate_header();
    tokenStackInit(&idStack);

    CHECK_AND_CALL_FUNCTION(FirstBody());

    return OK;
}

int fill_function_table()
{
    Symtable_init(&global_symbol_table);
    while (token.token_type != TT_EOF)
    {
        NEXT();
        if (token.token_type == TT_KEYWORD_FUNC)
        {
            CHECK_AND_CALL_FUNCTION(fast_func());
        }
    }
    rewind_file();
    return OK;
}

int insert_builtins()
{
    Symtable_item *print = create_item();
    print->token.attribute.string = malloc(sizeof(char) * strlen("print") + 1);
    print->isfunction = true;
    strcpy(print->token.attribute.string, "print");
    Symtable_insert(&global_symbol_table, "print", print);

    Symtable_item* inputs = create_item();
    inputs->token.attribute.string = malloc(sizeof(char)*strlen("inputs")+1);
    strcpy(inputs->token.attribute.string, "inputs");
    inputs->isfunction = true;
    inputs->parameter_count = 0;
    inputs->return_values_count = 2;
    inputs->dataType[0] = DT_STRING;
    inputs->dataType[1] = DT_INT;
    Symtable_insert(&global_symbol_table, "inputs", inputs);

    Symtable_item* inputi = create_item();
    inputi->token.attribute.string = malloc(sizeof(char)*strlen("inputi")+1);
    strcpy(inputi->token.attribute.string, "inputi");
    inputi->isfunction = true;
    inputi->parameter_count = 0;
    inputi->return_values_count = 2;
    inputi->dataType[0] = DT_INT;
    inputi->dataType[1] = DT_INT;
    Symtable_insert(&global_symbol_table, "inputi", inputi);

    Symtable_item* inputf = create_item();
    inputf->token.attribute.string = malloc(sizeof(char)*strlen("inputf")+1);
    strcpy(inputf->token.attribute.string, "inputf");
    inputf->isfunction = true;
    inputf->parameter_count = 0;
    inputf->return_values_count = 2;
    inputf->dataType[0] = DT_FLOAT;
    inputf->dataType[1] = DT_INT;
    Symtable_insert(&global_symbol_table, "inputf", inputf);

    Symtable_item* int2float = create_item();
    int2float->token.attribute.string = malloc(sizeof(char)*strlen("int2float")+1);
    strcpy(int2float->token.attribute.string, "int2float");
    int2float->isfunction = true;
    int2float->parameter_count = 1;
    int2float->return_values_count = 1;
    int2float->parameters = malloc(sizeof(Parameter)*int2float->parameter_count);
    int2float->parameters[0].dataType = DT_INT;
    int2float->dataType[0] = DT_FLOAT;
    Symtable_insert(&global_symbol_table, "int2float", int2float);

    Symtable_item* float2int = create_item();
    float2int->token.attribute.string = malloc(sizeof(char)*strlen("float2int")+1);
    strcpy(float2int->token.attribute.string, "float2int");
    float2int->isfunction = true;
    float2int->parameter_count = 1;
    float2int->return_values_count = 1;
    float2int->parameters = malloc(sizeof(Parameter)*float2int->parameter_count);
    float2int->parameters[0].dataType = DT_FLOAT;
    float2int->dataType[0] = DT_INT;
    Symtable_insert(&global_symbol_table, "float2int", float2int);

    Symtable_item* len = create_item();
    len->token.attribute.string = malloc(sizeof(char)*strlen("len")+1);
    strcpy(len->token.attribute.string, "len");
    len->isfunction = true;
    len->parameter_count = 1;
    len->return_values_count = 1;
    len->parameters = malloc(sizeof(Parameter)*len->parameter_count);
    len->parameters[0].dataType = DT_STRING;
    len->dataType[0] = DT_INT;
    Symtable_insert(&global_symbol_table, "len", len);

    Symtable_item* substr = create_item();
    substr->token.attribute.string = malloc(sizeof(char)*strlen("substr")+1);
    strcpy(substr->token.attribute.string, "substr");
    substr->isfunction = true;
    substr->parameter_count = 3;
    substr->return_values_count = 2;
    substr->parameters = malloc(sizeof(Parameter)*substr->parameter_count);
    substr->parameters[0].dataType = DT_STRING;
    substr->parameters[1].dataType = DT_INT;
    substr->parameters[2].dataType = DT_INT;
    substr->dataType[0] = DT_STRING;
    substr->dataType[1] = DT_INT;
    Symtable_insert(&global_symbol_table, "substr", substr);

    Symtable_item* ord = create_item();
    ord->token.attribute.string = malloc(sizeof(char)*strlen("ord")+1);
    strcpy(ord->token.attribute.string, "ord");
    ord->isfunction = true;
    ord->parameter_count = 2;
    ord->return_values_count = 2;
    ord->parameters = malloc(sizeof(Parameter)*ord->parameter_count);
    ord->parameters[0].dataType = DT_STRING;
    ord->parameters[1].dataType = DT_INT;
    ord->dataType[0] = DT_INT;
    ord->dataType[1] = DT_INT;
    Symtable_insert(&global_symbol_table, "ord", ord);

    Symtable_item *chr = create_item();
    chr->token.attribute.string = malloc(sizeof(char)*strlen("chr")+1);
    strcpy(chr->token.attribute.string, "chr");
    chr->isfunction = true;
    chr->parameter_count = 1;
    chr->return_values_count = 2;
    chr->parameters = malloc(sizeof(Parameter)*chr->parameter_count);
    chr->parameters[0].dataType = DT_INT;
    chr->dataType[0] = DT_STRING;
    chr->dataType[1] = DT_INT;
    Symtable_insert(&global_symbol_table, "chr", chr);
    return 0;
}

int fast_func()
{
    // Rule: <func> -> func id ( <params> ) <ret_types> { <stat_list> }
    char *function_name;
    Symtable_item *function = create_item();
    function->isfunction = true;
    EOL_allowed = false;

    CHECK_AND_LOAD_TOKEN(TT_KEYWORD_FUNC);
    if (token.token_type == TT_IDENTIFIER)
    {
        function_name = malloc(sizeof(*token.attribute.string) * strlen(token.attribute.string) + 1);
        strcpy(function_name, token.attribute.string);
        function->token.attribute.string = function_name;
    }
    else
    {
        return SYNTAX_ERROR;
    }
    NEXT()

    CHECK_AND_LOAD_TOKEN(TT_OPEN_PARENTHESES);
    CHECK_AND_CALL_FUNCTION(fast_params(function));
    CHECK_AND_LOAD_TOKEN(TT_CLOSE_PARENTHESES);

    CHECK_AND_CALL_FUNCTION(fast_ret_types(function));

    // Skip function body
    EOL_allowed = true;
    CHECK_AND_LOAD_TOKEN(TT_OPEN_BRACES);
    if (is_EOL == false)
    {
        return SYNTAX_ERROR;
    }
    is_EOL = false;
    int indent_count = 1;
    while (indent_count)
    {
        if (token.token_type == TT_EOF)
        {
            return SYNTAX_ERROR;
        }
        if (token.token_type == TT_OPEN_BRACES)
        {
            indent_count++;
        }
        if (token.token_type == TT_CLOSE_BRACES)
        {
            indent_count--;
        }
        if (indent_count > 0)
        {
            NEXT();
        }
    }

    Symtable_insert(&global_symbol_table, function_name, function);
    return OK;
}

int fast_params(Symtable_item *function)
{
    switch (token.token_type)
    {
    case TT_IDENTIFIER:
        // Rule: <params> -> <param> <params_n>
        CHECK_AND_CALL_FUNCTION(fast_param(function));
        CHECK_AND_CALL_FUNCTION(fast_params_n(function));
        return OK;
    case TT_CLOSE_PARENTHESES:
        // Rule: <params> -> eps
        return OK;
    default:
        return SYNTAX_ERROR;
    }
}

int fast_param(Symtable_item *function)
{
    // Rule: <param> -> id <data_type>
    if (token.token_type == TT_IDENTIFIER)
    {
        function->parameter_count++;
        if (function->parameters == NULL)
        {
            function->parameters = malloc(sizeof(Parameter) * function->parameter_count);
        }
        else
        {
            function->parameters = realloc(function->parameters, sizeof(Parameter) * function->parameter_count);
        }
        function->parameters[function->parameter_count - 1].identifier = malloc(sizeof(*token.attribute.string) * strlen(token.attribute.string) + 1);
        strcpy(function->parameters[function->parameter_count - 1].identifier, token.attribute.string);
    }
    else
    {
        return SYNTAX_ERROR;
    }
    NEXT()
    switch (token.token_type)
    {
    case TT_KEYWORD_FLOAT64:
        function->parameters[function->parameter_count - 1].dataType = DT_FLOAT;
        break;
    case TT_KEYWORD_INT:
        function->parameters[function->parameter_count - 1].dataType = DT_INT;
        break;
    case TT_KEYWORD_STRING:
        function->parameters[function->parameter_count - 1].dataType = DT_STRING;
        break;
    default:
        return SYNTAX_ERROR;
    }
    NEXT()
    return OK;
}

int fast_params_n(Symtable_item *function)
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:
        // Rule: <params_n> -> eps
        return OK;
    case TT_COMMA:
        // Rule: <params_n> -> , <param> <params_n>
        CHECK_AND_LOAD_TOKEN(TT_COMMA);
        CHECK_AND_CALL_FUNCTION(fast_param(function));
        CHECK_AND_CALL_FUNCTION(fast_params_n(function));
        return OK;
    default:
        return SYNTAX_ERROR;
    }
}

int fast_ret_types(Symtable_item *function)
{
    switch (token.token_type)
    {
    case TT_OPEN_PARENTHESES:
        // Rule: <ret_types> -> ( <types> )
        CHECK_AND_LOAD_TOKEN(TT_OPEN_PARENTHESES);
        CHECK_AND_CALL_FUNCTION(fast_types(function));
        CHECK_AND_LOAD_TOKEN(TT_CLOSE_PARENTHESES);
        return OK;
    case TT_OPEN_BRACES:
        // Rule: <ret_types> -> eps
        function->return_values_count = 0;
        return OK;
    case TT_KEYWORD_INT:
    case TT_KEYWORD_STRING:
    case TT_KEYWORD_FLOAT64:
        // Rule: <ret_types> -> <data_type>
        switch (token.token_type)
        {
        case TT_KEYWORD_INT:
            // Rule: <data_type> -> int
            CHECK_AND_LOAD_TOKEN(TT_KEYWORD_INT);
            function->dataType[0] = DT_INT;
            function->return_values_count = 1;
            return OK;
        case TT_KEYWORD_STRING:
            // Rule: <data_type> -> string
            CHECK_AND_LOAD_TOKEN(TT_KEYWORD_STRING);
            function->dataType[0] = DT_STRING;
            function->return_values_count = 1;
            return OK;
        case TT_KEYWORD_FLOAT64:
            // Rule: <data_type> -> float
            CHECK_AND_LOAD_TOKEN(TT_KEYWORD_FLOAT64);
            function->dataType[0] = DT_FLOAT;
            function->return_values_count = 1;
            return OK;
        default:
            return SYNTAX_ERROR;
        }
        return OK;
    default:
        return SYNTAX_ERROR;
    }
}

int fast_types(Symtable_item *function)
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:
        // Rule: <types> -> eps
        function->dataType[0] = DT_VOID;
        function->return_values_count = 1;
        return OK;
    case TT_KEYWORD_INT:
    case TT_KEYWORD_STRING:
    case TT_KEYWORD_FLOAT64:
        // Rule: <types> -> <data_type> <types_n>
        CHECK_AND_CALL_FUNCTION(fast_state_data_type(function));
        CHECK_AND_CALL_FUNCTION(fast_types_n(function));
        return OK;
    default:
        return SYNTAX_ERROR;
    }
}

int fast_state_data_type(Symtable_item *function)
{
    // Max 10 return values supported
    if (function->return_values_count == 10)
    {
        return INTERNAL_ERROR;
    }
    switch (token.token_type)
    {
    case TT_KEYWORD_INT:
        // Rule: <data_type> -> int
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_INT);
        function->dataType[function->return_values_count++] = DT_INT;
        return OK;
    case TT_KEYWORD_STRING:
        // Rule: <data_type> -> string
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_STRING);
        function->dataType[function->return_values_count++] = DT_STRING;
        return OK;
    case TT_KEYWORD_FLOAT64:
        // Rule: <data_type> -> float
        CHECK_AND_LOAD_TOKEN(TT_KEYWORD_FLOAT64);
        function->dataType[function->return_values_count++] = DT_FLOAT;
        return OK;
    default:
        return SYNTAX_ERROR;
    }
}

int fast_types_n(Symtable_item *function)
{
    switch (token.token_type)
    {
    case TT_CLOSE_PARENTHESES:
        // Rule: <types_n> -> eps
        return OK;
    case TT_COMMA:
        // Rule: <types_n> -> , <data_type> <types_n>
        CHECK_AND_LOAD_TOKEN(TT_COMMA);
        CHECK_AND_CALL_FUNCTION(fast_state_data_type(function));
        CHECK_AND_CALL_FUNCTION(fast_types_n(function));
        return OK;
    default:
        return SYNTAX_ERROR;
    }
}

int parse()
{
    Symtable_stack_init(&symtable_stack);
    Symstack_init(&expression_result_stack);
    // First data gathering pass
    return_code = fill_function_table();
    insert_builtins();
    if (return_code != OK)
    {
        return return_code;
    }
    NEXT();

    // Second full pass
    return_code = Start();
    Symtable_stack_dispose(&symtable_stack);
    return return_code;
}