CREATE TABLE Uzivatel (
    ID int primary key auto_increment ,
    Jmeno varchar(255) not null ,
    Prijmeni varchar(255) not null ,
    Heslo varchar(255) not null ,
    Titul varchar(255) ,
    Role varchar(255) not null ,
    Organizace varchar(255) ,
    Obor varchar(255) ,
    Zeme varchar(255) ,
    Datum_narozeni date ,
    Email varchar(255) not null ,
    TelCislo varchar(255) ,
    check ( Email regexp '.+@.+\..+') ,
    check ( TelCislo regexp '^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$' ) ,
    check ( Role = 'administrator' or Role = 'uzivatel' )
);

CREATE TABLE Konference (
    Nazev varchar(255) primary key ,
    Popis text,
    Obor varchar(255) not null ,
    Zeme varchar(255) not null ,
    Mesto varchar(255) not null ,
    Misto varchar(255) not null ,
    Zacatek_datum date not null ,
    Konec_datum date not null ,
    Zacatek_cas time not null ,
    Konec_cas time not null ,
    Poplatek int not null ,
    Cena_vstup int not null ,
    Kapacita int not null ,
    ZbyvajiciKapacita int ,
    Poradatel int ,
    Doplnujici_udaje text,
    check ( Konec_datum >= Zacatek_datum ),
    check (Zacatek_datum != Konec_datum or (Zacatek_datum = Konec_datum and Zacatek_cas < Konec_cas)) ,
    constraint FK_Poradatel foreign key (Poradatel) references Uzivatel(ID) on delete set null
);

CREATE TABLE Rezervace (
    ID int primary key auto_increment ,
    Konference varchar(255) not null ,
    Uzivatel int ,
    Jmeno varchar(255) ,
    Prijmeni varchar(255) ,
    Email varchar(255) ,
    Datum_vytvoreni datetime default CURRENT_TIMESTAMP,
    Pocet_vstupenek int not null ,
    Celkova_cena int not null ,
    Stav varchar(20) ,
    constraint FK_Konference foreign key (Konference) references Konference(Nazev) on delete cascade ,
    constraint FK_Uzivatel foreign key (Uzivatel) references Uzivatel(ID) on delete cascade ,
    check ( Stav = 'vytvoreno' or Stav = 'zaplaceno' ) ,
    check (Pocet_vstupenek >= 0) ,
    check (Celkova_cena >= 0) ,
    check ( Email regexp '.+@.+\..+')
);

CREATE TABLE Mistnost (
    Kod varchar(20) primary key ,
    Popis text ,
    Vybaveni varchar(255) ,
    Konference varchar(255) ,
    constraint FK_Konference_M foreign key (Konference) references Konference(Nazev) on delete cascade
);

CREATE TABLE Prezentace (
     ID int primary key auto_increment ,
     Nazev varchar(255) not null ,
     Konference varchar(255) ,
     Uzivatel int not null ,
     Popis text ,
     Tagy varchar(255) ,
     Grafika varchar(255) ,
     Soubor text ,
     Mistnost varchar(20) ,
     jeSchvalena bool ,
     Datum date ,
     Zacatek_cas time ,
     Konec_cas time ,
     poznamkyPoradatele text,
     constraint FK_Konference_P foreign key (Konference) references Konference(Nazev) on delete set null ,
     constraint FK_Mistnost foreign key (Mistnost) references Mistnost(Kod) on delete set null ,
     constraint FK_Prezentuje foreign key (Uzivatel) references Uzivatel(ID) on delete cascade
);

