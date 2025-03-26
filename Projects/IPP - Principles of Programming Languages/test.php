#!/usr/bin/env php
<?php
ini_set('display_errors', 'stderr');

$total_tests = 0;
$ok_tests = 0;
$failed_tests = 0;

/*
 * Generovanie hlavicky html na standardny vystup
 */
function generate_html_start()
{
    echo "<!DOCTYPE html>\n";
    echo "<html lang=\"cz\">\n";
    echo "<head>\n";
    echo "<title>Test.php - IPP</title>\n";
    echo "<style>\n";
    echo "table, th, td { \n";
    echo "border: 1px solid black;}\n";
    echo "</style>\n";
    echo "</head>\n";
    echo "<body>\n";
    echo "<center><h2>IPP 2021 - test.php</h2><br></center>\n";

    echo "<table style=\"width:100%\">\n";
    echo "<tr>\n";
    echo "<th>Cislo testu</th>\n";
    echo "<th>Nazov testu</th>\n";
    echo "<th>Umiestnenie</th>\n";
    echo "<th>RC</th>\n";
    echo "<th>Spravny RC</th>\n";
    echo "<th>Vysledok</th>\n";
    echo "<th>Pricina</th>\n";
    echo "</tr>\n";
}

/*
 * Generovanie html statistik testov na standardny vystup
 */
function generate_html_stats()
{
    echo "<h3> --- Test sum: --- <br>\n";
    echo "<p style=\"color:green\">Uspesne:   " . $GLOBALS["ok_tests"] . "</p>\n";
    echo "<p style=\"color:red\">Neuspesne: " . $GLOBALS["failed_tests"] . "</p>\n";
    echo "<p style=\"color:blue\">Celkom: " . $GLOBALS["total_tests"] . "</p>\n";
    if ($GLOBALS["total_tests"] != 0) {
        $uspesnost = (100 / $GLOBALS["total_tests"]) * $GLOBALS["ok_tests"];
    } else {
        $uspesnost = 0;
    }
    echo "<p style=\"color:coral\">Uspesnost: " . $uspesnost . "% </p>\n";
    echo "</h3>";
}

/*
 * Generovanie konca html suboru na standardny vystup
 */
function generate_html_end()
{
    echo "</body>\n";
    echo "</html>\n";
}

/*
 * Vytvori subory .in, .out, .src ak chybaju
 *
 * directory - cesta k suboru
 * file - nazov pozadovaneho suboru
 */
function create_if_missing_files($directory, $file)
{
    if (!file_exists($directory . $file . '.in')) {
        $new_file = fopen($directory . $file . '.in', 'w');
        fclose($new_file);
    }
    if (!file_exists($directory . $file . '.out')) {
        $new_file = fopen($directory . $file . '.out', 'w');
        fclose($new_file);
    }
    if (!file_exists($directory . $file . '.rc')) {
        $new_file = fopen($directory . $file . '.rc', 'w');
        fwrite($new_file, '0');
        fclose($new_file);
    }
}

/*
 * Overenie spravnej cesty k jednotlivym suborom - existencia daneho suboru
 *
 * $directory, $int_only, $parse_script, $parse_only, $int_script, $jexamxml, $jexamcfg - cesty jednotlivych suborov
 * exit 41 - subor sa nepodarilo otvorit
 */
function check_files_location($directory, $int_only, $parse_script, $parse_only, $int_script, $jexamxml, $jexamcfg)
{
    if (!file_exists($directory)) {
        fwrite(STDERR, "cesta $directory neexistuje\n");
        exit(41);
    }
    if ($int_only == false) {
        if (!file_exists($parse_script)) {
            fwrite(STDERR, "subor $parse_script neexistuje\n");
            exit(41);
        }
    }
    if ($parse_only == false) {
        if (!file_exists($int_script)) {
            fwrite(STDERR, "subor $int_script neexistuje\n");
            exit(41);
        }
    }
    if (!file_exists($jexamxml)) {
        fwrite(STDERR, "subor $jexamxml neexistuje\n");
        exit(41);
    }
    if (!file_exists($jexamcfg)) {
        fwrite(STDERR, "subor $jexamcfg neexistuje\n");
        exit(41);
    }
}

/*
 * Overenie zakazanych kombinacii parametrov
 *
 * exit 10 - je pouzita zakazana kombinacia parametrov
 */
function chceck_deny_parameters($int_only, $parse_only, $parse_script_bool, $int_script_bool)
{
    if (($int_only == true) and ($parse_only == true)) {
        fwrite(STDERR, "int_only a parse_only sa nesmu kombinovat\n");
        exit(10);
    } elseif (($int_only == true) and ($parse_script_bool == true)) {
        fwrite(STDERR, "int_only a parse_script sa nesmu kombinovat\n");
        exit(10);
    } elseif (($parse_only == true) and ($int_script_bool == true)) {
        fwrite(STDERR, "parse_only a int_script sa nesmu kombinovat\n");
        exit(10);
    }
}

/*
 * Vypis napovedy na standardny vystup
 */
function printing_help()
{
    echo "*** NAPOVEDA skriptu test.php ***\n" .
        "Skript slouzi pro automaticke testovani aplikace parse.php\n" .
        "a aplikace interpret.py\n" .
        "---- Pouzite parametre: ------\n" .
        "--help - zobrazi tuto napovedu\n" .
        "--directory=path - testy bude hladat v zvolenom adresari\n" .
        "--recursive - testy nebude hladat iba v adresari testu, ale rekurzivne aj v jeho podadresaroch\n" .
        "--parse-script=file - subor so skriptom parse.php - ak chyba tak hladam parse.php v aktualnom adresari\n" .
        "--int-script=file - subor so skriptom interpret.py v Python 3.8\n" .
        "--parse-only - testujem iba skript pre analyzu kodu IPPcode21\n" .
        "--int-only - testujem iba skript pre interpret kodu IPPcode21\n" .
        "--jexamxml=file - subor s JAR balickom s nastrojom A7Soft JExamXML\n" .
        "--jexamcfg=file - subor s konfiguraciou nastroja A7Soft JExamXML\n";
}

/*
 * Vypis spustnych parametrov pri teste
 *
 * directory - cesta k suboru
 * parse_script - cesta k skriptu parse.php
 * int_script - cesta k skriptu interpret.py
 * jexamxml - cesta k suboru jexamxml.jar
 * jexamcfg - cesta ku konfiguracnemu suboru jexamxml
 * recursive - prameter --recursive
 * parse_only - parameter --parse-only
 * int_only - parameter --int-only
 */
function print_test_parameters($directory, $parse_script, $int_script, $jexamxml, $jexamcfg, $recursive, $parse_only, $int_only)
{
    echo "<h3> ---- Parametre test.php: ----</h3>\n";
    if ($recursive == true) {
        echo "--directory = rekurzivne prechadzane<br>\n";
    } else {
        echo "--directory = $directory <br>\n";
    }
    echo "--parse-script = $parse_script <br>\n";
    echo "--int-script = $int_script <br>\n";
    echo "--jexamxml = $jexamxml <br>\n";
    echo "--jexamcfg = $jexamcfg <br>\n";
    echo "<h3> ---- Aktivovane parametre: ----</h3>\n";
    if ($recursive == true) {
        echo "--recursive<br>\n";
    }
    if ($parse_only == true) {
        echo "--parse_only<br>\n";
    }
    if ($int_only == true) {
        echo "--int_only<br>\n";
    }
}

/*
 * Vypis noveho riadku do tabulky testov pre kazdy test na standardny vystup
 *
 * file - nazov testu
 * directory - cesta k suboru
 * ref_return_code - referencny navratovy kod
 * my_return_code - moj navratovy kod
 * result - OK/FALSE - OK pre uspesny test, inak FALSE
 * why - doplnkovy parameter priciny zlyhania testu - pri result OK obsahuje prazdny retazec
 */
function print_test_result($file, $directory, $ref_return_code, $my_return_code, $result, $why)
{
    echo "<tr>\n";
    echo "<th>" . $GLOBALS["total_tests"] . "</th>\n";
    echo "<th>" . $file . "</th>\n";
    echo "<th>" . $directory . "</th>\n";
    echo "<th>" . $my_return_code . "</th>\n";
    echo "<th>" . $ref_return_code . "</th>\n";
    if ($result == "OK") {
        echo "<th><font color=\"green\">" . $result . "</font></th>\n";
    } else {
        echo "<th><font color=\"red\">" . $result . "</font></th>\n";
    }
    echo "<th>" . $why . "</th>\n";
    echo "</tr>\n";
}

function run_interpret($parser, $parsed_output, $int_script, $directory, $file, $ref_return_code)
{
    $output = "";
    //prebehlo spracuvanie parsrom - source nacitaj z docastneho suboru parsra
    if ($parser == true) {
        exec('python3 ' . $int_script . ' --source=' . $parsed_output . ' < ' . $directory . '/' . $file . '.in 1>tmp_output_interpret 2>/dev/null', $output, $interpret_return_code);
    } else { //neprebeho spracuvanie parsrom
        exec('python3 ' . $int_script . ' --source=' . $directory . '/' . $file . '.src ' . ' < ' . $directory . '/' . $file . '.in 1>tmp_output_interpret 2>/dev/null', $output, $interpret_return_code);
    }
    //return code interpretu je zhodny s referencnym RC
    if ($ref_return_code == $interpret_return_code) {
        //RC je 0 -> pouzijem diff
        if ($interpret_return_code == 0) {
            exec('diff tmp_output_interpret ' . $directory . "/" . $file . '.out', $output, $diff_return_code);
            //vystupy su zhodne
            if ($diff_return_code == 0) {
                $result = "OK";
                $why = "";
                print_test_result($file, $directory, $ref_return_code, $interpret_return_code, $result, $why);
                $GLOBALS["ok_tests"]++;
            } //diff hlasi nezhodu vo vystupoch
            else {
                $result = "FAILED";
                $why = "interpret.py - porovnanie diff";
                print_test_result($file, $directory, $ref_return_code, $interpret_return_code, $result, $why);
                $GLOBALS["failed_tests"]++;
            }
        } //RC nie je 0, ale je zhodny s referencnym
        else {
            $result = "OK";
            $why = "";
            print_test_result($file, $directory, $ref_return_code, $interpret_return_code, $result, $why);
            $GLOBALS["ok_tests"]++;
        }
    } //RC nie je zhodny s referencnym RC testu
    else {
        $result = "FAILED";
        $why = "interpret.py - RC sa nezhoduje";
        print_test_result($file, $directory, $ref_return_code, $interpret_return_code, $result, $why);
        $GLOBALS["failed_tests"]++;
    }
    exec('rm -f tmp_output_interpret');
}

//defaultne nastavenie hodnot
$directory = getcwd() . '/';
$recursive = false;
$parse_script = getcwd() . "/parse.php";
$parse_script_bool = false;
$int_script = getcwd() . "/interpret.py";
$int_script_bool = false;
$parse_only = false;
$int_only = false;
$jexamxml = "/pub/courses/ipp/jexamxml/jexamxml.jar";
$jexamcfg = "/pub/courses/ipp/jexamxml/options";

//prehladavanie vsetkych parametrov test.php pre najdenie parametru --help
$help_with_another_param = false;
$print_help = false;
for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] == '--help') {
        $print_help = true;
    } else {
        $help_with_another_param = true;
    }

}
//overenie ze bol zadany parameter --help, overenie pripadnych zakazanych kombinacii s parametrom --help
if (($print_help == true) and ($help_with_another_param == false)) {
    printing_help();
    exit(0);
} elseif (($print_help == true) and ($help_with_another_param == true)) {
    fwrite(STDERR, "Parameter help nesmie obsahovat ine parametre\n");
    exit(10);
}

//Parsovanie vstupnych parametrov testu
for ($i = 1; $i < $argc; $i++) {
    $argv_explode = explode("=", $argv[$i]);

    if ($argv_explode[0] == "--directory") { //--directory
        $argv_explode = explode("=", $argv[$i]);
        if (!array_key_exists(1, $argv_explode)) {
            fwrite(STDERR, "nezadana cesta k suboru directory\n");
            exit(10);
        }
        //pridanie znaku '/' ak chyba v parametri --directory
        if (substr($argv_explode[1], -1) == "/") {
            $directory = $argv_explode[1];
        } else {
            $directory = $argv_explode[1] . "/";
        }
    } elseif ($argv_explode[0] == "--recursive") { //--recursive
        $recursive = true;
    } elseif ($argv_explode[0] == "--parse-script") { //--parse-script
        if (!array_key_exists(1, $argv_explode)) {
            fwrite(STDERR, "nezadana cesta k suboru parse-script\n");
            exit(10);
        }
        $parse_script = $argv_explode[1];
        $parse_script_bool = true;
    } elseif ($argv_explode[0] == "--int-script") { //--int-script
        if (!array_key_exists(1, $argv_explode)) {
            fwrite(STDERR, "nezadana cesta k suboru int-script\n");
            exit(10);
        }
        $int_script = $argv_explode[1];
        $int_script_bool = true;
    } elseif ($argv_explode[0] == "--parse-only") { //--parse-only
        $parse_only = true;
    } elseif ($argv_explode[0] == "--int-only") { //--int-only
        $int_only = true;
    } elseif ($argv_explode[0] == "--jexamxml") { //--jexamxml
        if (!array_key_exists(1, $argv_explode)) {
            fwrite(STDERR, "nezadana cesta k suboru jexamxml\n");
            exit(10);
        }
        $jexamxml = $argv_explode[1];
    } elseif ($argv_explode[0] == "--jexamcfg") { //--jexamcfg
        if (!array_key_exists(1, $argv_explode)) {
            fwrite(STDERR, "nezadana cesta k suboru jexamcfg\n");
            exit(10);
        }
        $jexamcfg = $argv_explode[1];
    } else {    //--mimo povolenych argumentov
        fwrite(STDERR, "Invalid argument\n");
        exit(10);
    }
}

chceck_deny_parameters($int_only, $parse_only, $parse_script_bool, $int_script_bool);
check_files_location($directory, $int_only, $parse_script, $parse_only, $int_script, $jexamxml, $jexamcfg);
generate_html_start();

$directories = array();
//Ak je zadany parameter --recursvie, ulozim vsetky priecinky, ktore budem prechadzat
if ($recursive == true) {
    $directories = explode("\n", shell_exec('find ' . $directory . ' -type d 2>/dev/null'));
} else {
    $directories = explode("\n", $directory);
}

foreach ($directories as $directory2) {
    $GLOBALS["directory"] = $directory2;
    if (substr($directory, -1) != "/") { //overenie ci obsahuje cesta znak '/'
        $directory = $directory . "/";
    }
    $files = explode("\n", shell_exec('ls ' . $directory . ' 2>/dev/null | grep .src'));
    foreach ($files as $file) { //prehladam vsetky subory s priponou *.src
        $file = str_replace('.src', '', $file); //odstran priponu .src suboru
        if ($file == "") { //preskocenie neexistujucich adresarov
            continue;
        } elseif ($file == ".") {
            continue;
        } elseif ($file == "..") {
            continue;
        }

        create_if_missing_files($directory, $file);
        $GLOBALS["total_tests"]++;

        // *********** Parse.php *********
        if ($int_only == false) {
            $output = NULL;
            exec('cat ' . $directory . $file . '.src | php7.4 ' . $parse_script . '> tmp_output_parser 2>/dev/null', $output, $parser_return_code); //spustenie skriptu parse.php
            $ref_return_code_file = fopen($directory . '/' . $file . '.rc', 'r'); //nacitanie suboru s pozadovanym RC
            $ref_return_code = fgets($ref_return_code_file); //nacitanie pozadovaneho RC

            //parameter --parse-only bol zadany
            if ($parse_only == true) {
                //RC parsru je zhodny s referencnym RC
                if ($ref_return_code == $parser_return_code) {
                    //RC je 0 a mam parameter --parse-only -> pouzijem JExamXML na porovnanie
                    if ($parser_return_code == 0) {
                        exec('java -jar ' . $jexamxml . ' tmp_output_parser ' . $directory . $file . ".out delta.xml " . $jexamcfg, $output, $jexamxml_return_code);

                        //JExamXml - rovnake subory
                        if ($jexamxml_return_code == 0) {
                            $result = "OK";
                            $why = "";
                            print_test_result($file, $directory, $ref_return_code, $parser_return_code, $result, $why);
                            $GLOBALS["ok_tests"]++;
                        } //JExamXml - odlisne subory - chyba parser
                        else {
                            $result = "FAILED";
                            $why = "parse.php - JExamXM (odlisne subory)";
                            print_test_result($file, $directory, $ref_return_code, $parser_return_code, $result, $why);
                            $GLOBALS["failed_tests"]++;
                        }

                    } //RC nieje 0, ale je zhodny s referencnym RC -> nepouzivam JExamXML
                    else {
                        $result = "OK";
                        $why = "";
                        print_test_result($file, $directory, $ref_return_code, $parser_return_code, $result, $why);
                        $GLOBALS["ok_tests"]++;
                    }
                } //RC nie je zhodny s referencnym
                else {
                    $result = "FAILED";
                    $why = "parse.php - RC sa nezhoduje";
                    print_test_result($file, $directory, $ref_return_code, $parser_return_code, $result, $why);
                    $GLOBALS["failed_tests"]++;
                }
            } //parameter --parse-only nebol zadany - spust interpret s parsrovym vystupom
            else {
                $parsed_output = "tmp_output_parser";
                $parser = true;
                run_interpret($parser, $parsed_output, $int_script, $directory, $file, $ref_return_code);
            }
            //zmaz docasne vytvorene subory
            exec('rm -f delta.xml');
            exec('rm -f tmp_output_parser.log');
            exec('rm -f tmp_xml_test');
            exec('rm -f tmp_output_parser');
            fclose($ref_return_code_file);
        }

        // *********** Interpret.py *********
        if ($int_only == true) { //bez vystupu parsru
            $ref_return_code_file = fopen($directory . '/' . $file . '.rc', 'r');
            $ref_return_code = fgets($ref_return_code_file);
            $parsed_output = "";
            $parser = false;
            run_interpret($parser, $parsed_output, $int_script, $directory, $file, $ref_return_code);
            fclose($ref_return_code_file);
        }
    }
}

echo "</table>";
generate_html_stats();
print_test_parameters($directory, $parse_script, $int_script, $jexamxml, $jexamcfg, $recursive, $parse_only, $int_only);
generate_html_end();