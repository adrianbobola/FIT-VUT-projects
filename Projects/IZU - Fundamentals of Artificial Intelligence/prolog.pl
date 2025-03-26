% Zadání č. 28:
% Napište program řešící úkol daný predikátem u28(LIN,LOUT), kde LIN je 
% vstupní seznam a LOUT je výstupní seznam obsahující všechny prvky seznamu
% LIN rotované o jedno místo doprava. 

% Testovací predikáty:                                 	% LOUT 
u28_1:- u28([a,b,c,d,e],LOUT),write(LOUT).				% [e, a, b, c, d]
u28_2:- u28([],LOUT),write(LOUT).                       % [] 
u28_3:- u28([123],LOUT),write(LOUT).                    % [123]
u28_r:- write('Zadej LIN: '),read(LIN),
	u28(LIN,LOUT),write(LOUT).

u28(LIN,LOUT):- riesenie(LIN, LOUT).

vloz_novy_prvok(T, H, [T|H]).

zisti_posledny_prvok([H|T], S) :- T == [], S = H, !.
zisti_posledny_prvok([_|T], S) :- zisti_posledny_prvok(T, S).

odstran_posledny_prvok([_], []) :- true, !.
odstran_posledny_prvok([H|T], [H|T2]) :- odstran_posledny_prvok(T, T2). 

riesenie([], LOUT) :- LOUT = [], !. 
riesenie(LIN, LOUT):- zisti_posledny_prvok(LIN, POSLEDNY), vloz_novy_prvok(POSLEDNY, LIN, LHELP), 
    odstran_posledny_prvok(LHELP, LOUT).