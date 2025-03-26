/*
21, Výpočet součinu všech prvků seznamu čísel typu Integer kromě nulových
uloha21(SEZNAM, SOUCIN)
% SEZNAM je seznam čísel typu Integer, SOUCIN je hodnota
% vyjadřující součin všech čísel v seznamu kromě nulových
*/

uloha21([],0).
uloha21([SEZNAM], SEZNAM).

uloha21([H1, H2|T], SOUCIN) :- H1 = 0, 
   uloha21([H2|T], SOUCIN).

uloha21([H|T], SOUCIN) :- H \= 0,
    uloha21(T, Rest),
    Rest \= 0,
    SOUCIN is H * Rest.

uloha21([H|T], SOUCIN) :- H \= 0,
    uloha21(T, Rest),
    Rest = 0,
    SOUCIN is H.
