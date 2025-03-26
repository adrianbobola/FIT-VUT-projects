#include "parser.h"
#include "codegen.h"
#include "scanner.h"

int main()
{
    int scanner_file_return = set_file(stdin);
    if (scanner_file_return == -1)
    {
        fprintf(stderr, "Failed to open file");
        return 99;
    }

    set_code_output(stdout);
    int parse_return = parse();
    //Force flush before exit
    fflush(stdout);
    fflush(stderr);
    return parse_return;
}
