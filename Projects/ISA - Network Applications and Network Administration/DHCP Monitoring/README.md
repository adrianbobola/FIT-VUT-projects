# dhcp-stats

	author: Adrian Bobola (xbobol00)
	date: 2023-11-20

## NAME

       dhcp-stats - generuje statistiku vytazenia sietoveho prefixu v DHCP

## SYNOPSIS

       dhcp-stats [-r file-name] [-i interface-name] [<IP/prefix> [...]]

## DESCRIPTION

dhcp-stats je program urceny ku generovaniu statistiky vytazenia sietoveho prefixu, zadaneho v prikazovej riadke, v DHCP komunikacii.
Aplikacia generuje statistiku zo vstupneho suboru alebo zo sietoveho rozhrania do okna aplikacie.

Hodnoty vytazenia prefixov sa aktualizuju v okne automaticky.
Pri prekroceni 50% vytazenia zadaneho IP prefixu dojde k zapisu tejto hlasky do syslogu a do okna programu.

## OPTIONS

    -r file-name
        Meno analyzovaneho .pcap suboru v aktualnom adresari.
        Je pozadovane pouzit parameter -r alebo -i.

    -i interface-name
        Nazov sietoveho rozhrania na ktorom bude prebiehat monitorovanie DHCP komunikacie.
        Je pozadovane pouzit parameter -r alebo -i.

    <IP/prefix> [...]
        Obsahuje vsetky pozadovane analyzovane IP adresy vratane prefixu.
        Zapisujte v tvare "IP/prefix".
        Jednotlive IP adresy musia byt oddelene medzerami.
        
## FILES

	dhcp-stats.cpp, Makefile, manual.pdf, dhcp-stats.1, README.md
