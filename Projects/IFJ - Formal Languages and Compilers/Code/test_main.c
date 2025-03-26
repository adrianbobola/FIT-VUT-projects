#include "scanner.h"
#include <string.h>
#include "symtable.h"
#include "symtablestack.h"
#include "testData.h"
#include "parser.h"
#include "codegen.h"

FILE* test_file = NULL;

int setup(char * string){
    init_test_data();
    test_file = tmpfile();
    fprintf(test_file, "%s", string);
    rewind(test_file);
    if (set_file(test_file) == -1){
        fprintf(stderr, "Invalid input file");
        return 1;
    }
    set_code_output(stdout);
    return 0;
}

int test_no_errors(char * string){
    if (setup(string)){
        fprintf(stderr, "Error setting up test environment");
        return 1;
    }
    Token token;
    for(int i = 0;next_token(&token);i++){
        if (token.token_type == TT_ERR){
            return 1;
        }
        if (i > 1000){
            fprintf(stderr, "Over 1000 tokens generated. Probably stuck in an infinite loop");
            return 1;
        }
    }
    if (token.token_type != TT_EOF){
        return 1;
    }
    return 0;
}

int test_exact_token_sequence(char * string, Token* expected){
    if (setup(string)){
        fprintf(stderr, "Error setting up test environment");
        return 1;
    }
    Token scanned;
    for(int i = 0; next_token(&scanned); i++){
        if (expected[i].token_type == scanned.token_type){
            switch (expected[i].token_type) {
                case TT_IDENTIFIER:
                case TT_STRING_LITERAl:
                    if (strcmp(expected[i].attribute.string, scanned.attribute.string) != 0){
                        fprintf(stderr, "String \"%s\" does dot match \"%s\"", scanned.attribute.string, expected[i].attribute.string);
                        return 1;
                    }
                    break;
                case TT_INTEGER_LITERAL:
                    if (expected[i].attribute.integer != scanned.attribute.integer){
                        fprintf(stderr, "Integer attribute %ld does dot match %ld", scanned.attribute.integer, expected[i].attribute.integer);
                        return 1;
                    }
                    break;
                case TT_FLOATING_LITERAL:
                    if (expected[i].attribute.floating != scanned.attribute.floating){
                        fprintf(stderr, "Float %f does dot match %f", scanned.attribute.floating, expected[i].attribute.floating);
                        return 1;
                    }
                    break;
                default:
                    break; // No attribute
            }
        } else {
            fprintf(stderr, "Token type %d does not match %d", scanned.token_type, expected[i].token_type);
            return 1;
        }
    }
    return 0;
}

int test_symtable(){
    Symtable_node_ptr symtable;
    Symtable_init(&symtable);

    Symtable_item* new_item = create_item();
    new_item->dataType[0] = DT_INT;
    Symtable_item* item = Symtable_insert(&symtable, "var", new_item);
    if (new_item != item){
        fprintf(stderr, "Item insert failed!\n");
        return 1;
    }

    Symtable_item* new_item_2 = create_item();
    new_item_2->dataType[0] = DT_STRING;
    item = Symtable_insert(&symtable, "str", new_item_2);
    if (new_item_2 != item){
        fprintf(stderr, "Item insert failed!\n");
        return 1;
    }

    Symtable_delete(&symtable, "var");

    if (new_item_2 != Symtable_search(symtable, "str")){
        fprintf(stderr, "Item search failed!\n");
        return 1;
    }

    Symtable_dispose(&symtable);

    return 0;
}

int test_symtable_stack(){
    // Initialize stack
    Symtable_stack* stack;
    Symtable_stack_init(&stack);

    // Init symbol table with 1 item
    Symtable_node_ptr symtable;
    Symtable_init(&symtable);
    Symtable_insert(&symtable, "var", create_item());

    // Init empty symbol table
    Symtable_node_ptr symtable2;
    Symtable_init(&symtable2);

    // Insert symbol tables onto the stack
    Symtable_stack_insert(stack, symtable);
    if (stack->top != 0){
        fprintf(stderr, "Stack top is %d an should be 0", stack->top);
        return 1;
    }
    Symtable_stack_insert(stack, symtable2);
    if (stack->top != 1){
        fprintf(stderr, "Stack top is %d an should be 1", stack->top);
        return 1;
    }

    // Pop out one
    free_symtable_node(Symtable_stack_pop(stack));
    // Pop out second symbol table and check that it is the same we put in
    Symtable_node_ptr popped_symtable = Symtable_stack_pop(stack);
    if (popped_symtable != symtable){
        fprintf(stderr, "Symtable_stack_pop returned wrong table");
        return 1;
    }
    free_symtable_node(popped_symtable);
    // Check that the stack is now empty
    if (Symtable_stack_head(stack) != NULL){
        fprintf(stderr, "Symstack is not empty");
        return 1;
    }
    // Cleanup
    Symtable_stack_dispose(&stack);
    return 0;
}

int print_tokens(char * string){
    if (setup(string)){
        fprintf(stderr, "Error setting up test environment");
        return 1;
    }
    Token token;
    while (next_token(&token)){
        printf("%d - \"%s\"\n", token.token_type, to_string_attribute(&token));
    }
    return 0;
}

int test_return_value(char * input, int expected){
    if (setup(input)){
        fprintf(stderr, "Error setting up test environment");
        return 1;
    }
    int parse_return = parse();
    if (parse_return != expected){
        fprintf(stderr, "TEST: Expected return code %d but found %d", expected, parse_return);
        return 1;
    }
    return 0;
}

int main(){
    if(test_no_errors(TESTDATA_FACTORIAL_ITERATIVE)){
        printf("TEST 1 FAILED\n");
        return 1;
    }
    if(test_no_errors(TESTDATA_FACTORIAL_RECURSIVE)){
        printf("TEST 2 FAILED\n");
        return 1;
    }
    if(test_no_errors(TESTDATA_STRING_FUNCTION_EXAMPLE)){
        printf("TEST 3 FAILED\n");
        return 1;
    }
    if (test_exact_token_sequence(TESTDATA_STRING_LITERALS, TESTDATA_STRING_LITERALS_TOKENS)){
        printf("TEST 4 FAILED\n");
        return 1;
    }
    if(test_symtable()){
        printf("TEST 6 FAILED\n");
        return 1;
    }
    if(test_symtable_stack()){
        printf("TEST 7 FAILED\n");
        return 1;
    }
    if (test_return_value("package main\n\nfunc oznuk(test string) (int) {\n    return 0\n}\n"
                          "\n"
                          "func main () int {\n"
                          ""
                          "}", 0)){
        return 1;

    }
    return 0;
}