import argparse
import xml.etree.ElementTree as ElementTree
import sys

# --------- Spracuvanie argumentov --------------------------

parser = argparse.ArgumentParser("IPP 2021: Interpret")
parser.add_argument("--source", metavar="source", nargs=1, type=str, help="Interpret.py - Napoveda skriptu")
parser.add_argument("--input", metavar="input", nargs=1, type=str, help="Interpret.py - Napoveda skriptu")
argumentParse = parser.parse_args()

# nebol zadany ziaden parameter
if (argumentParse.source is None) and (argumentParse.input is None):
    sys.stderr.write("Nebol zadany ani jeden parameter")
    sys.exit(10)

# nebol zadany parameter --input - STDIN
if argumentParse.input is None:
    input_file = sys.stdin
else:
    try:
        input_file = open(''.join(argumentParse.input), "r")
    # nedokazem otvorit zadany subor
    except IOError:
        sys.stderr.write("Neviem otvorit subor zadany v --input")
        sys.exit(11)

# nebol zadany parameter --source - STDIN
if argumentParse.source is None:
    source_file = sys.stdin
else:
    try:
        source_file = open(''.join(argumentParse.source), "r")
    # nedokazem otvorit zadany subor
    except IOError:
        sys.stderr.write("Neviem otvorit subor zadany v --source")
        sys.exit(11)


# -------- testovanie XML suboru ------------------------

# nacitanie XML suboru do struktury stromu
try:
    tree = ElementTree.parse(source_file)
except IOError:
    sys.stderr.write("Neviem otvorit subor zadany v --source")
    sys.exit(11)
except ElementTree.ParseError:
    sys.stderr.write("Neocakavana XML struktura")
    sys.exit(31)

root = tree.getroot()
# testovanie korena
if root.tag != 'program':
    sys.stderr.write("Neocakavana XML struktura")
    sys.exit(32)

# prechadzam dict korena s atributmi a hladam language
for item in root.attrib:
    if (item == "language"):
        if (root.attrib[item] != "IPPcode21"):
            sys.stderr.write("XML subor neobsahuje polozku IPPcode21")
            sys.exit(32)
 
# hladam instruction u syna
for child in root:
    if (child.tag != "instruction"):
        sys.stderr.write("XML subor neobsahuje polozku instruction")
        sys.exit(32)
        
    for params in child: # neobsahuje arg1
        if params.tag != "arg1":
            sys.stderr.write("XML subor neobsahuje arg1")
            sys.exit(32)
