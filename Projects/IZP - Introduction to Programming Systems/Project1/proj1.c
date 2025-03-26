/*
    Author:  Adrian Bobola, xbobol00@stud.fit.vutbr.cz
    Name:    Project n.1 for IZP 2019/2020 FIT VUT
    Date:    November 2019
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
// Max chars count in one line
#define LINE_CHARS 101

//  Converting name to phone-keyboard name [E,T,C = 3,8,2] If input is a...z return phone-key-number, else return input value
char char_to_keynumber(int character);
// Search substring in string, return True or False
bool search_data(char *searchword, char *number);
// Print all contacts without search name or number. Return False for stdin error, else return True
bool printall();
// Read data from stdin and covert to lower-case characters. Return False for stdin error, else return True
bool read_data(char *searchword);

int main(int argc, char *argv[]) {
    if (argc == 1) {
        if (printall() == false) {
            fprintf(stderr, "%s", "Bad stdin format or length of string! \n");
            return 2;
        }
        return 0;
    }
    if (strlen(argv[1]) > LINE_CHARS) {     // Too long argument
        fprintf(stderr, "%s", "LENGTH OF ARGUMENT! \n");
        return 1;
    }
    if (argc == 2) {    // One argument - run search
        char search_word[LINE_CHARS + 1];
        strncpy(search_word, argv[1], LINE_CHARS + 1);
        for (int i = 0; i < (int)strlen(search_word); i++) {
            if (search_word[i] > 57) {
                fprintf(stderr, "%s", "ARGUMENT CONTAINS CHARACTER! \n");
                return 1;
            }
        }
        if (read_data(search_word) == false) { // Loaded line has more than LINE_CHARS characters or alphabet in number
            fprintf(stderr, "%s", "Bad stdin format or length of string! \n");
            return 2;
        }
    } else {
        fprintf(stderr, "%s", "MORE THAN 1 ARG! \n");
        return 3;
    }
    return 0;
}

bool read_data(char *searchword) {
    unsigned int char_counter = 0;
    unsigned int line_counter = 0;
    unsigned int output_counter = 0;
    char name_number[3][LINE_CHARS + 1] = {0}; // 1 is for name, 2 is for number, 3 is for name in phone-keyboard
    int c = getchar();

    while (c != EOF) {
        if (char_counter == LINE_CHARS) {
            return false;
        }
        if ((line_counter == 1) && (c > 57)) {  // char is alphabet while reading number
            return false;
        }

        if (c == 10) {  // LF char
            char_counter++;
            name_number[line_counter][char_counter] = '\0'; // Add string-end char
            line_counter++;
            if (line_counter == 2) {    // All data is loaded, start search
                if ((search_data(searchword, name_number[1])) || (search_data(searchword, name_number[2]))) {
                    printf("%s, ", name_number[0]);
                    printf("%s\n", name_number[1]);
                    output_counter++;
                }
                memset(name_number, 0, sizeof(name_number));
                line_counter = 0;
            }
            char_counter = 0;
            c = getchar();
        }
        if (c >= 'A' && c <= 'Z') { // Change from A..Z to a..z
            c += 32;
        }
        name_number[line_counter][char_counter] = c;
        if (line_counter == 0) {
            name_number[2][char_counter] = char_to_keynumber(c);
        }
        char_counter++;
        c = getchar();
    }
    if (output_counter == 0) {
        printf("Not found\n");
    }
    return true;
}

bool printall() {
    unsigned int char_counter = 0;
    unsigned int line_counter = 0;
    int c = getchar();
    char name_number[3][101] = {0};

    while (c != EOF) {
        if (char_counter == LINE_CHARS) {
            return false;
        }
        if ((line_counter == 1) && (c > 57)) {  // char is alphabet while reading number
            return false;
        }
        if (c == 10) {  //LF
            char_counter++;
            name_number[line_counter][char_counter] = '\0';
            line_counter++;
            if (line_counter == 2) {
                printf("%s, ", name_number[0]);
                printf("%s\n", name_number[1]);
                memset(name_number, 0, sizeof(name_number));
                line_counter = 0;
            }
            char_counter = 0;
            c = getchar();
        }
        name_number[line_counter][char_counter] = c;
        char_counter++;
        c = getchar();
    }
    return true;
}

char char_to_keynumber(int character) {
    switch (character) {
        case 43:
            return 48;
        case 97 ... 99:
            return 50;
        case 100 ... 102:
            return 51;
        case 103 ... 105:
            return 52;
        case 106 ... 108:
            return 53;
        case 109 ... 111:
            return 54;
        case 112 ... 115:
            return 55;
        case 116 ... 118:
            return 56;
        case 119 ... 122:
            return 57;
        default:
            return (char) character;
    }
}

bool search_data(char *searchword, char *number) {
    if (strstr(number, searchword) != NULL) {
        return true;
    }
    return false;
}
