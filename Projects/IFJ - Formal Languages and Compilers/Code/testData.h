#ifndef IFJ20C_TESTDATA_H
#define IFJ20C_TESTDATA_H

#include <stdbool.h>

bool data_initialized;

// For happy path testing
static char* TESTDATA_FACTORIAL_ITERATIVE = "// Program 1: Vypocet faktorialu (iterativne)\npackage main\n\nfunc main() {\n  print(\"Zadejte cislo pro vypocet faktorialu: \")\n  a := 0\n  a, _ = inputi()\n  if a < 0 {\n  print(\"Faktorial nejde spocitat!\\n\")\n  } else {\n    for vysl := 1; a > 0; a = a - 1 {\n    vysl = vysl * a\n  }\n  print(\"Vysledek je \", vysl, \"\\n\")\n}\n}\n";
static char* TESTDATA_FACTORIAL_RECURSIVE = "// Program 2: Vypocet faktorialu (rekurzivne)\npackage main\nfunc factorial(n int) (int) {\ndec_n := n - 1\nif n < 2 {\nreturn 1\n} else {\ntmp := factorial(dec_n)\nreturn n * tmp\n}\n}\nfunc main() {\nprint(\"Zadejte cislo pro vypocet faktorialu: \")\na := 0\na, err = inputi()\nif err == 0 {\nif a < 0 {\nprint(\"Faktorial nejde spocitat!\", \"\\n\")\n} else {\nvysl := factorial(a)\nprint(\"Vysledek je \", vysl, \"\\n\")\n}\n} else {\nprint(\"Chyba pri nacitani celeho cisla!\\n\")\n}\n}\n";
static char* TESTDATA_STRING_FUNCTION_EXAMPLE = "// Program 3: Prace s ěretzci a vestavenymi funkcemi\npackage main\n11\nfunc main() {\ns1 := \"Toto je nejaky text\"\ns2 := s1 + \", ktery jeste trochu obohatime\"\nprint(s1, \"\\n\", s2)\ns1len := 0\ns1len = len(s1)\ns1len = s1len - 4\ns1, _ = substr(s2, s1len, 4)\ns1len = s1len + 1\nprint(\"4 znaky od\", s1len, \". znaku v \\\"\", s2, \"\\\":\", s1, \"\\n\")\nprint(\"Zadejte serazenou posloupnost vsem malych pismen a-h, \")\nprint(\"pricemz se pismena nesmeji v posloupnosti opakovat: \")\nerr := 0\ns1, err = inputs()\nif err != 1 {\nfor ;s1 != \"abcdefgh\"; {\nprint(\"\\n\", \"Spatne zadana posloupnost, zkuste znovu:\")\ns1, _ = inputs()\n}\n} else {\n}\n}\n";
// String literal test with escape sequences
static char* TESTDATA_STRING_LITERALS="\"String literal test \\x40 \\n \\\\ \\t\"";
Token TESTDATA_STRING_LITERALS_TOKENS[2];

void init_test_data(){
    if (!data_initialized){
        data_initialized = true;
        TESTDATA_STRING_LITERALS_TOKENS[0].token_type = TT_STRING_LITERAl;
        TESTDATA_STRING_LITERALS_TOKENS[0].attribute.string = "String literal test \x40 \n \\ \t";
        TESTDATA_STRING_LITERALS_TOKENS[1].token_type = TT_EOF;
    }
}


#endif //IFJ20C_TESTDATA_H
