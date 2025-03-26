<?php

define('INSTR_VAR', '/^((GF|TF|LF)@([\p{L}_\-$&%*!?][\p{L}_\-$&%*!?0-9]*))$/');
define('INSTR_SYMB', '/^((GF|TF|LF)@([\p{L}À-ȕ0-9_\-$&%*!?<>]*)|(bool@true)|(bool@false)|(nil@nil)|(int@[-+]*[0-9][0-9]*)|(string@(([\\\\][0-9][0-9][0-9])*[\p{L}0-9À-ȕ$&%*\'\"!=?\/@§<>(),\-_.,; ]*)*)|(string@))$/');
define('INSTR_LABEL', '/^([\p{L}_\-$&%*!?][\p{L}0-9_\-$&%*!?]*)$/');
define('INSTR_TYPE', '/^(int|bool|string)$/');

ini_set('display_errors', 'stderr');
$header = false;
$header_counter = 0;
$instr_order = 1;

/*
Funkcia: incorrect_arg_count
Param1: pole argumentov
Param2: pozadovany pocet argumentov
Return: True-nespravny pocet arg, False-spravny pocet arg
*/
function incorrect_arg_count(array $arg_array, int $arg_count)
{
    if (count($arg_array) != $arg_count) {
        return true;
    }

    return false;
}

/*
Funkcia: write_symbol
Param1: retazec
Param2: poradie vypisovaneho argumentu
Return: True-spravny retazec, False-nevalidny retazec
*/
function write_symbol(string $string, int $arg_count)
{
    if (preg_match('/^int@.*/', $string)) {
        echo "\t\t<arg$arg_count type=\"int\">";
        echo preg_replace('/^int@/', '', $string);
        echo "</arg$arg_count>\n";

        return true;
    } elseif (preg_match('/^bool@.*/', $string)) {
        echo "\t\t<arg$arg_count type=\"bool\">";
        echo preg_replace('/^bool@/', '', $string);
        echo "</arg$arg_count>\n";

        return true;
    } elseif (preg_match('/^nil@nil/', $string)) {
        echo "\t\t<arg$arg_count type=\"nil\">";
        echo 'nil';
        echo "</arg$arg_count>\n";

        return true;
    } elseif (preg_match('/^(LF|TF|GF)@.*/', $string)) {
        echo "\t\t<arg$arg_count type=\"var\">";
        echo preg_replace('/^nil@/', '', $string);
        echo "</arg$arg_count>\n";

        return true;
    } elseif (preg_match('/^string@.*/', $string)) {
        echo "\t\t<arg$arg_count type=\"string\">";
        $helper = preg_replace('/^string@/', '', $string);
        $helper = str_replace(['&', '<', '>', '"', "'"], ['&amp;', '&lt;', '&gt;', '&quot;', '&apos;'], $helper); //zmen nevalidne znaky na XML validne
        echo $helper;
        echo "</arg$arg_count>\n";

        return true;
    }

    return false;
}

if ($argc >= 2) {
    if ($argv[1] == '--help') {
        echo "*** NAPOVEDA ***\n";
        echo "Skript nacte ze standardniho vstupu zdrojovy kod v IPPcode21,\n";
        echo "zkontroluje lexikalni a syntaktickou spravnost kodu\n";
        echo "a vypise na standardni vystup XML reprezentaci programu.\n";
        exit(0);
    } else {
        exit(10);
    }
}

echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
while ($line = fgets(STDIN)) {
    if (($line == "\n") || (preg_match('~^\s*#~', $line))) { //Ignoruje prazdne riadky + komentare na zaciatku
        continue;
    }
    $line = preg_replace('/\s+/', ' ', $line);
    $line = trim(preg_replace('/#.*$/', '', $line));
    $linetrimmed = trim($line, "\n");
    $splitted = explode(' ', $linetrimmed);

    if ($header == false) {
        if (strtoupper($splitted[0]) == '.IPPCODE21') {
            $header = true;
            echo "<program language=\"IPPcode21\">\n";
        } else {
            exit(21);
        }
    }

    switch (strtoupper($splitted[0])) {
        case 'MOVE':
        case 'INT2CHAR':
        case 'STRLEN':
        case 'TYPE':
            if (incorrect_arg_count($splitted, 3)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if ((preg_match(INSTR_VAR, $splitted[1])) && (preg_match(INSTR_SYMB, $splitted[2]))) {
                echo "\t\t<arg1 type=\"var\">$splitted[1]</arg1>\n";
                if (write_symbol($splitted[2], 2) == false) {
                    exit(23);
                }
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'CREATEFRAME':
        case 'PUSHFRAME':
        case 'POPFRAME':
        case 'RETURN':
        case 'BREAK':
            if (incorrect_arg_count($splitted, 1)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\"/>\n";
            ++$instr_order;
            break;

        case 'DEFVAR':
        case 'POPS':
            if (incorrect_arg_count($splitted, 2)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if (preg_match(INSTR_VAR, $splitted[1])) {
                echo "\t\t<arg1 type=\"var\">$splitted[1]</arg1>\n";
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'CALL':
            if (incorrect_arg_count($splitted, 2)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if (preg_match(INSTR_LABEL, $splitted[1])) {
                echo "\t\t<arg1 type=\"label\">$splitted[1]</arg1>\n";
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'PUSHS':
        case 'WRITE':
        case 'EXIT':
        case 'DPRINT':
            if (incorrect_arg_count($splitted, 2)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if (preg_match(INSTR_SYMB, $splitted[1])) {
                if (write_symbol($splitted[1], 1) == false) {
                    exit(23);
                }
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'READ':
            if (incorrect_arg_count($splitted, 3)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if (preg_match(INSTR_VAR, $splitted[1])) {
                echo "\t\t<arg1 type=\"var\">$splitted[1]</arg1>\n";
                if (preg_match(INSTR_TYPE, $splitted[2])) {
                    echo "\t\t<arg2 type=\"type\">$splitted[2]</arg2>\n";
                    echo "\t</instruction>\n";
                } else {
                    exit(23);
                }
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'ADD':
        case 'SUB':
        case 'MUL':
        case 'IDIV':
        case 'LT':
        case 'GT':
        case 'EQ':
        case 'AND':
        case 'OR':
        case 'STRI2INT':
        case 'CONCAT':
        case 'GETCHAR':
        case 'SETCHAR':
            if (incorrect_arg_count($splitted, 4)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if ((preg_match(INSTR_VAR, $splitted[1])) && (preg_match(INSTR_SYMB, $splitted[2])) && (preg_match(INSTR_SYMB, $splitted[3]))) {
                echo "\t\t<arg1 type=\"var\">$splitted[1]</arg1>\n";
                if (write_symbol($splitted[2], 2) == false) {
                    exit(23);
                }
                if (write_symbol($splitted[3], 3) == false) {
                    exit(23);
                }
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'NOT':
            if (count($splitted) == 4) { // 3 argumenty
                echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
                if ((preg_match(INSTR_VAR, $splitted[1])) && (preg_match(INSTR_SYMB, $splitted[2])) && (preg_match(INSTR_SYMB, $splitted[3]))) {
                    echo "\t\t<arg1 type=\"var\">$splitted[1]</arg1>\n";
                    if (write_symbol($splitted[2], 2) == false) {
                        exit(23);
                    }
                    if (write_symbol($splitted[3], 3) == false) {
                        exit(23);
                    }
                    echo "\t</instruction>\n";
                } else {
                    exit(23);
                }
                ++$instr_order;
                break;
            } elseif (count($splitted) == 3) { // 4 argumenty
                echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
                if ((preg_match(INSTR_VAR, $splitted[1])) && (preg_match(INSTR_SYMB, $splitted[2]))) {
                    echo "\t\t<arg1 type=\"var\">$splitted[1]</arg1>\n";
                    if (write_symbol($splitted[2], 2) == false) {
                        exit(23);
                    }
                    echo "\t</instruction>\n";
                } else {
                    exit(23);
                }
                ++$instr_order;
                break;
            } else {
                exit(23);
            }

        case 'LABEL':
        case 'JUMP':
            if (incorrect_arg_count($splitted, 2)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if (preg_match(INSTR_LABEL, $splitted[1])) {
                echo "\t\t<arg1 type=\"label\">$splitted[1]</arg1>\n";
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case 'JUMPIFEQ':
        case 'JUMPIFNEQ':
            if (incorrect_arg_count($splitted, 4)) {
                exit(23);
            }
            echo "\t<instruction order=\"$instr_order\" opcode=\"$splitted[0]\">\n";
            if ((preg_match(INSTR_LABEL, $splitted[1])) && (preg_match(INSTR_SYMB, $splitted[2])) && (preg_match(INSTR_SYMB, $splitted[3]))) {
                echo "\t\t<arg1 type=\"label\">$splitted[1]</arg1>\n";
                if (write_symbol($splitted[2], 2) == false) {
                    exit(23);
                }
                if (write_symbol($splitted[3], 3) == false) {
                    exit(23);
                }
                echo "\t</instruction>\n";
            } else {
                exit(23);
            }
            ++$instr_order;
            break;

        case '.IPPCODE21':
            $header_counter++;
            if (incorrect_arg_count($splitted, 1)) {
                exit(23);
            } elseif ($header_counter > 1) {
                exit(22);
            }
            break;

        default:
            exit(22);
    }
}
echo "</program>\n";
exit(0);
