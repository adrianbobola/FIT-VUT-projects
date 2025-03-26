# IFJ PROJECT 2020
cmake_minimum_required(VERSION 3.10.2)

project(ifj20c LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE Debug)

# IFJ20 Library
add_library(libifj20c
        scanner.c scanner.h
        token.c token.h
        symtable.c symtable.h
        parser.c parser.h
        return-codes.h
        symstack.c symstack.h
        symtablestack.c symtablestack.h
        precedence.c precedence.h
        codegen.c codegen.h
        token_stack.c token_stack.h)

# IFJ20C Tests
add_executable(test_libifj20c test_main.c)
target_link_libraries(test_libifj20c PUBLIC libifj20c)
# IFJ20C
add_executable(${PROJECT_NAME} main.c)
target_link_libraries(${PROJECT_NAME} PUBLIC libifj20c)