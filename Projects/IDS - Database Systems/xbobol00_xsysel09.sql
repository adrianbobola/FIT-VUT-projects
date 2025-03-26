-- IDS 2020/2021 | Autor: XBOBOL00, XSYSEL09

DROP TABLE Aliance CASCADE CONSTRAINTS;
DROP TABLE Kapitan CASCADE CONSTRAINTS;
DROP TABLE Lod CASCADE CONSTRAINTS;
DROP TABLE Pirat CASCADE CONSTRAINTS;
DROP TABLE Posadka CASCADE CONSTRAINTS;
DROP TABLE Pristav CASCADE CONSTRAINTS;
DROP TABLE Radovy_pirat CASCADE CONSTRAINTS;
DROP TABLE Bitva CASCADE CONSTRAINTS;
DROP TABLE Pirat_veli_lod CASCADE CONSTRAINTS;
DROP TABLE Lod_bojovala_v_bitva CASCADE CONSTRAINTS;

DROP SEQUENCE pirat_seq;
DROP PROCEDURE lode_s_vetsou_kapacitou_nez;
DROP PROCEDURE rozirene_informace_lodi;
--DROP INDEX bitva_id_lod_index;
DROP MATERIALIZED VIEW barva_vousu_piratu;

CREATE TABLE Pirat
(
    id              INT PRIMARY KEY,
    jmeno           VARCHAR(80) CHECK (REGEXP_LIKE(jmeno, '([[:graph:]]{2,}?)+')), -- min 2 znaky za sebou
    prezdivka       VARCHAR(80)  NOT NULL,
    vek             INT          NOT NULL CHECK ( vek > 0 ),
    barva_vousu     VARCHAR(80)  NOT NULL,
    cas_sluzby      DATE,
    charakteristiky VARCHAR(255) NOT NULL,
    plavi_se_na     INT
);

CREATE TABLE Radovy_pirat
(
    id         INT PRIMARY KEY,
    pozice     VARCHAR(80),
    je_soucast VARCHAR(20)
);

CREATE TABLE Kapitan
(
    id INT PRIMARY KEY
);

CREATE TABLE Posadka
(
    jmeno         VARCHAR(20) PRIMARY KEY CHECK (REGEXP_LIKE(jmeno, '([[:graph:]]{2,}?)+')), -- min 2 znaky za sebou
    jolly_roger   VARCHAR(255) NOT NULL,
    tvori_alianci VARCHAR(80),
    vlastni       INT          NOT NUll
);

CREATE TABLE Lod
(
    id       INT GENERATED AS IDENTITY NOT NULL PRIMARY KEY,
    typ      VARCHAR(80)               NOT NULL,
    kapacita INT                       NOT NULL CHECK ( kapacita > 0 ),
    patri    INT,
    kotvi    INT

);

CREATE TABLE Pirat_veli_lod
(
    id       INT GENERATED AS IDENTITY PRIMARY KEY,
    id_pirat INT NOT NULL,
    id_lod   INT NOT NULL,
    CONSTRAINT pirat_veli_fk FOREIGN KEY (id_pirat) REFERENCES Pirat (id) ON DELETE CASCADE,
    CONSTRAINT lod_veli_fk FOREIGN KEY (id_lod) REFERENCES Lod (id) ON DELETE CASCADE
);

CREATE TABLE Pristav
(
    id            INT GENERATED AS IDENTITY PRIMARY KEY,
    nazev_ostrova VARCHAR(80) NOT NULL CHECK (REGEXP_LIKE(nazev_ostrova, '([[:graph:]]{2,}?)+')), -- min 2 znaky za sebou
    kapacita      INT         NOT NULL CHECK ( kapacita > 0 ),
    je_teritorium VARCHAR(20)
);

CREATE TABLE Aliance
(
    nazev   VARCHAR(80) PRIMARY KEY CHECK (REGEXP_LIKE(nazev, '([[:graph:]]{2,}?)+')), -- min 2 znaky za sebou
    sidli_v INT
);

CREATE TABLE Bitva
(
    id         INT GENERATED AS IDENTITY PRIMARY KEY,
    datum      DATE NOT NULL,
    ztraty     INT  NOT NULL CHECK ( ztraty >= 0 ),
    probehla_v INT
);

CREATE TABLE Lod_bojovala_v_bitva
(
    id       INT GENERATED as IDENTITY PRIMARY KEY,
    id_lod   INT NOT NULL,
    id_bitva INT NOT NULL,
    CONSTRAINT lod_bojovala_fk FOREIGN KEY (id_lod) REFERENCES Lod (id) ON DELETE CASCADE,
    CONSTRAINT bitva_bojovala_fk FOREIGN KEY (id_bitva) REFERENCES Bitva (id) ON DELETE CASCADE
);

ALTER TABLE Lod
    ADD CONSTRAINT patri_fk FOREIGN KEY (patri) REFERENCES Kapitan (id) ON DELETE SET NULL;
ALTER TABLE Lod
    ADD CONSTRAINT kotvi_fk FOREIGN KEY (kotvi) REFERENCES Pristav (id) ON DELETE SET NULL;
ALTER TABLE Pirat
    ADD CONSTRAINT plavi_se_na_fk FOREIGN KEY (plavi_se_na) REFERENCES Lod (id) ON DELETE SET NULL;
ALTER TABLE Kapitan
    ADD CONSTRAINT kapitan_fk FOREIGN KEY (id) REFERENCES Pirat (id) ON DELETE CASCADE;
ALTER TABLE Posadka
    ADD CONSTRAINT tvori_alianci_fk FOREIGN KEY (tvori_alianci) REFERENCES Aliance (nazev) ON DELETE SET NULL;
ALTER TABLE Posadka
    ADD CONSTRAINT vlastni_fk FOREIGN KEY (vlastni) REFERENCES Kapitan (id) ON DELETE CASCADE;
ALTER TABLE Radovy_pirat
    ADD CONSTRAINT pirat_fk FOREIGN KEY (id) REFERENCES Pirat (id) ON DELETE CASCADE;
ALTER TABLE Radovy_pirat
    ADD CONSTRAINT je_soucast_fk FOREIGN KEY (je_soucast) REFERENCES Posadka (jmeno) ON DELETE SET NULL;
ALTER TABLE Pristav
    ADD CONSTRAINT je_teritorium_fk FOREIGN KEY (je_teritorium) REFERENCES Posadka (jmeno) ON DELETE SET NULL;
ALTER TABLE Aliance
    ADD CONSTRAINT sidli_v_fk FOREIGN KEY (sidli_v) REFERENCES Pristav (id) ON DELETE SET NULL;
ALTER TABLE Bitva
    ADD CONSTRAINT probleha_v_fk FOREIGN KEY (probehla_v) REFERENCES Pristav (id) ON DELETE SET NULL;

------------------------------------------------------------------------
-------------------------- TRIGGRE - PROJ 4+5---------------------------
------------------------------------------------------------------------

-- TRIGGER 1 ----------
-- Ak je pri vkladani zaznamu do tabulky ID_pirata NULL, priradi mu ID pirata
CREATE SEQUENCE pirat_seq;
CREATE OR REPLACE TRIGGER Kontrola_id_pirata
    BEFORE INSERT OR UPDATE
    ON Pirat
    FOR EACH ROW
    WHEN (NEW.id is NULL)
BEGIN
    :NEW.id := pirat_seq.NEXTVAL;
END;

-- TRIGGER 2 ----------
-- Overenie kapacity lode kotviacej v pristave. Ak je kapacita lode > kapacita pristavu, zavola sa vynimka a lod nezakotvi
CREATE OR REPLACE TRIGGER kontrola_kapacity_pristavu
    BEFORE INSERT OR UPDATE
    ON Lod
    FOR EACH ROW
    WHEN (OLD.kotvi IS NULL AND NEW.kotvi IS NOT NULL)
DECLARE
    full_capacity EXCEPTION;
    max_kapacita int;
BEGIN
    SELECT kapacita INTO max_kapacita FROM Pristav WHERE (Pristav.id = :NEW.kotvi);
    IF (max_kapacita < :NEW.kapacita) THEN
        :NEW.kotvi := NULL;
        RAISE full_capacity;
    END IF;

EXCEPTION
    WHEN full_capacity THEN
        DBMS_OUTPUT.ENABLE(buffer_size => NULL);
        dbms_output.PUT_LINE('Kapacita lode je vacsia ako kapacita pristavu v ktorej kotvi');
END;

-------------------------------------------------------------
------------------------ Insert Values ----------------------
-------------------------------------------------------------

--pirat
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES (NULL, 'Pirát z Karibiku', 45, 'Hneda, cerna', DATE '1999-8-1', 'Podezřele často se propadává podlahou.', NULL);

INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('John Dohn', 'Šavlozubý', 69, 'stříbrná', DATE '1975-1-20', 'Kulhá, nedoslýchá, páska přes oko.', NULL);

INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES (NULL, 'Červený šátek', 1, 'blond', DATE '2000-1-1', 'popáleniny na levé ruce', NULL);

-- radovy pirat
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Pirát z Karibiku'), NULL, NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE jmeno = 'John Dohn'), NULL, NULL);
--kapitan
INSERT INTO Kapitan (id)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Červený šátek'));
-- lod
INSERT INTO Lod (typ, kapacita, patri, kotvi)
VALUES ('Vikingská Briga', '6', (SELECT id FROM Pirat WHERE prezdivka = 'Červený šátek'), NULL);
INSERT INTO Lod (typ, kapacita, patri, kotvi)
VALUES ('Člun', '2', (SELECT id FROM Pirat WHERE prezdivka = 'Červený šátek'), NULL);
-- pridat vztah: pirat se plavi na lod
UPDATE Pirat
SET plavi_se_na = (SELECT id
                   from Lod
                   WHERE patri IN (SELECT id from Pirat WHERE prezdivka = 'Červený šátek')
                     and typ = 'Vikingská Briga')
WHERE prezdivka = 'Pirát z Karibiku'
   OR prezdivka = 'Šavlozubý'
   or prezdivka = 'Červený šátek';
-- posadka
INSERT INTO Posadka (jmeno, jolly_roger, tvori_alianci, vlastni)
VALUES ('Johnnyho banda', 'Černá lebka na černém pozadí', NULL,
        (SELECT id FROM Pirat WHERE prezdivka = 'Červený šátek'));
-- pristav
INSERT INTO Pristav (nazev_ostrova, kapacita, je_teritorium)
VALUES ('Celjón', 50, (SELECT jmeno FROM Posadka WHERE jmeno = 'Johnnyho banda'));
INSERT INTO Pristav (nazev_ostrova, kapacita, je_teritorium)
VALUES ('Jáva', 10, NULL);
-- aliance
INSERT INTO Aliance (nazev, sidli_v)
VALUES ('Východní obchodní společnost', (SELECT id FROM Pristav WHERE nazev_ostrova = 'Celjón'));
-- bitva
INSERT INTO Bitva (datum, ztraty, probehla_v)
VALUES (DATE '2015-08-03', 40, (SELECT id FROM Pristav WHERE nazev_ostrova = 'Celjón'));
-- radovy pirat - doplneni
UPDATE Radovy_pirat
SET pozice     = 'Kormidelník',
    je_soucast = 'Johnnyho banda'
WHERE id in (SELECT id FROM Pirat where prezdivka = 'Pirát z Karibiku');
-- radovy pirat - doplneni
UPDATE Radovy_pirat
SET pozice     = 'Tesar',
    je_soucast = 'Johnnyho banda'
WHERE id in (SELECT id FROM Pirat where prezdivka = 'Šavlozubý');
-- lod - doplneni udaju
UPDATE Lod
SET kotvi = (SELECT id FROM Pristav where nazev_ostrova = 'Celjón')
WHERE patri in (SELECT id FROM Pirat where prezdivka = 'Červený šátek');
-- posadka - doplneni
UPDATE Posadka
SET tvori_alianci = 'Východní obchodní společnost'
WHERE vlastni in (SELECT id FROM Pirat where prezdivka = 'Červený šátek');
-- doplneni vztahu
INSERT INTO Pirat_veli_lod (id_pirat, id_lod)
VALUES ((SELECT id FROM Pirat where prezdivka = 'Červený šátek'),
        (SELECT id
         FROM Lod
         where patri in ((SELECT id FROM Pirat where prezdivka = 'Červený šátek'))
           and typ = 'Vikingská Briga'));
-- doplneni vztahu
INSERT INTO Lod_bojovala_v_bitva (id_lod, id_bitva)
VALUES ((SELECT id
         FROM Lod
         where patri in ((SELECT id FROM Pirat where prezdivka = 'Červený šátek'))
           and typ = 'Vikingská Briga'),
        (SELECT id FROM Bitva WHERE datum = DATE '2015-08-03'));

----------------------Třetí projekt----------------------

--spojení dvou tabulek
--Kteří piráti jsou kapitány?
SELECT *
FROM Pirat
NATURAL JOIN Kapitan;

--spojení dvou tabulek
--Kolik volných míst mají jednotlivé lodě?
SELECT Lod.id                                Lod_id,
       Lod.kapacita - COUNT(UNIQUE Pirat.id) volnych_mist
FROM Lod
         LEFT JOIN Pirat ON plavi_se_na = Lod.id
GROUP BY Lod.id, Lod.kapacita;

--spojení tří tabulek
--Ve kterém přístavu kotví kteří piráti?
SELECT
    Pirat.id id_pirata,
    Pirat.prezdivka,
    Pristav.id id_pristavu,
    Pristav.nazev_ostrova
FROM Pirat
    LEFT JOIN Lod on Pirat.plavi_se_na = Lod.id
    LEFT JOIN Pristav on Lod.kotvi = Pristav.id;


--klauzule GROUP BY a agregační funkce
--Kolik je pirátů mladších 30 let?
SELECT COUNT(DISTINCT Pirat.id) pocet
FROM Pirat
WHERE Pirat.vek < 30
GROUP BY Pirat.vek;

--klauzule GROUP BY a agregační funkce
--Kolik lodí vlastní jednotlivé posádky?
SELECT Posadka.jmeno, COUNT(DISTINCT Lod.id) pocet_lodi
FROM POSADKA
         JOIN Lod on Posadka.vlastni = Lod.patri
GROUP BY Posadka.jmeno
ORDER BY pocet_lodi;

--predikát EXISTS
--Na kterých lodích se nikdo neplaví?
SELECT *
FROM Lod
WHERE NOT EXISTS(
    SELECT * FROM Pirat
    WHERE plavi_se_na = Lod.id
    );

--predikát IN s vnořeným SELECTem
--Které lodě patří pirátovy s přezdívkou Červený šátek?
SELECT *
FROM Lod
WHERE patri IN (
    SELECT id
    FROM Pirat
    WHERE prezdivka = 'Červený šátek'
    );

-------------------- Projekt 4,5----------------------------------------------------------------------------------------

INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('Johan Emanuel', 'Ostrá břitva', 40, 'blond', DATE '2000-8-4', 'tetování na hrudi, dredy', NULL);
INSERT INTO Kapitan (id)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Ostrá břitva'));
INSERT INTO Posadka (jmeno, jolly_roger, tvori_alianci, vlastni)
VALUES ('Severní vítr', 'Rozbité bílé hodiny na černém pozadí.', NULL,
        (SELECT id FROM Pirat WHERE prezdivka = 'Červený šátek'));

INSERT INTO Lod (typ, kapacita, patri, kotvi)
VALUES ('Vikingská Briga', '30', (SELECT id FROM Pirat WHERE prezdivka = 'Ostrá břitva'), NULL);
INSERT INTO Lod (typ, kapacita, patri, kotvi)
VALUES ('Vikingská galéra', '99', (SELECT id FROM Pirat WHERE prezdivka = 'Ostrá břitva'), NULL);
INSERT INTO Lod (typ, kapacita, patri, kotvi)
VALUES ('Vikingský knarr', '7', (SELECT id FROM Pirat WHERE prezdivka = 'Ostrá břitva'), NULL);

INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES (NULL, 'Levý', 18, 'černé', DATE '1997-12-1', 'popáleniny na levé ruce', NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Levý'), 'Koš', 'Severní vítr');
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('Don Brown', 'Plameňák', 25, 'zrzavé', DATE '2007-6-24', 'malá popálenina na tváři, gelované vlasy', NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Plameňák'), 'Kormidelník', 'Severní vítr');
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('Jan Novák', 'Čech', 37, 'blond', DATE '2013-3-18', 'bystré oči, útlé ruce, nepřirozeně vysoký', NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Čech'), 'Koš', 'Severní vítr');
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('Alexander Schmidt', 'Deutcsh', 28, 'blond', DATE '1995-5-20', 'vždy nosí čepici', NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Deutcsh'), 'Loďmistr', 'Severní vítr');
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('James Smith', 'Texasan', 32, 'černé', DATE '2017-9-27', 'nosí velký zatočený knír', NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'Texasan'), 'Navigátor', 'Severní vítr');
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES ('John Jolton', 'JoJo', 41, 'hnědé', DATE '2016-4-12', 'velmi muskulární', NULL);
INSERT INTO Radovy_pirat (id, pozice, je_soucast)
VALUES ((SELECT id FROM Pirat WHERE prezdivka = 'JoJo'), 'Dělostřelec', 'Severní vítr');

INSERT INTO Bitva (datum, ztraty, probehla_v)
VALUES (DATE '2017-10-12', 0, NULL);
INSERT INTO Lod_bojovala_v_bitva (id_lod, id_bitva)
VALUES ((SELECT id
         FROM Lod
         where patri in ((SELECT id FROM Pirat where prezdivka = 'Ostrá břitva'))
           and typ = 'Vikingská galéra'),
        (SELECT id FROM Bitva WHERE datum = DATE '2017-10-12'));
INSERT INTO Lod_bojovala_v_bitva (id_lod, id_bitva)
VALUES ((SELECT id
         FROM Lod
         where patri in ((SELECT id FROM Pirat where prezdivka = 'Ostrá břitva'))
           and typ = 'Vikingská Briga'),
        (SELECT id FROM Bitva WHERE datum = DATE '2017-10-12'));
INSERT INTO Lod_bojovala_v_bitva (id_lod, id_bitva)
VALUES ((SELECT id
         FROM Lod
         where patri in ((SELECT id FROM Pirat where prezdivka = 'Červený šátek'))
           and typ = 'Vikingská Briga'),
        (SELECT id FROM Bitva WHERE datum = DATE '2017-10-12'));

-----------------------------------------------------------------------------
----------------------------- TRIGGRE ---------------------------------------
-----------------------------------------------------------------------------
-- implementacia na riadku c.125

---------------- DEMONSTRACIA triggru 1 ----------
-- Vlozenie noveho pirata s ID = NULL, ID sa generuje triggrom 1
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES (NULL, 'Pirat zelenac', 25, 'Černá', NULL, 'nema', NULL);
--trigger 1
SELECT *
FROM Pirat;
-- Pridany pirat ma ID 11

---------------- DEMONSTRACIA triggru 2 ----------
-- Vlozenie lodi s kapacitou 10 000 pre trigger 2
--  Ak je kapacita lode > ako kapacita pristavu, nastavi parameter kotvi v na null a zavola sa vynimka
INSERT INTO Lod (typ, kapacita, patri, kotvi)
VALUES ('tanker', '10000', NULL, NULL);
UPDATE Lod
SET kotvi = (SELECT id FROM Pristav where nazev_ostrova = 'Celjón')
WHERE (typ = 'tanker');
--trigger 2
SELECT *
FROM Lod;

----------------------------------------------------------------------------
------------------------ PROCEDURY -----------------------------------------
----------------------------------------------------------------------------

---------- Procedura 1 --------
-- vypis lodi, ktore maju vacsiu kapacitu ako je zadana
CREATE OR REPLACE PROCEDURE lode_s_vetsou_kapacitou_nez(hledana_kapacita Lod.kapacita%TYPE) AS
    CURSOR lode_cursor IS SELECT *
                          FROM Lod;
    zkoumana_lod Lod%ROWTYPE;
    celkem_lodi  INT;
    vyhovuje     INT;
BEGIN
    vyhovuje := 0;
    celkem_lodi := 0;
    OPEN lode_cursor;
    DBMS_OUTPUT.ENABLE(buffer_size => NULL);
    DBMS_OUTPUT.PUT_LINE('Vypis lodi s kapacitou vacsou nez ' || hledana_kapacita || ':');
    DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------------');
    LOOP
        FETCH lode_cursor INTO zkoumana_lod;
        EXIT WHEN lode_cursor%notfound;
        celkem_lodi := celkem_lodi + 1;
        if zkoumana_lod.kapacita >= hledana_kapacita then
            vyhovuje := vyhovuje + 1;
            DBMS_OUTPUT.PUT_LINE(
                        'ID lode: ' || zkoumana_lod.ID || ', Jej typ: ' || zkoumana_lod.typ || ', Kapacita :' ||
                        zkoumana_lod.kapacita);
        END IF;
    END LOOP;
    DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('Pocet vsetkych lodi: ' || celkem_lodi);
    DBMS_OUTPUT.PUT_LINE('Vyhovuje: ' || vyhovuje);
    DBMS_OUTPUT.PUT_LINE('Zastupenie: ' || ((100 / celkem_lodi) * vyhovuje) || '%.');

EXCEPTION
    WHEN ZERO_DIVIDE THEN
        BEGIN
            DBMS_OUTPUT.PUT_LINE('Nie su ziadne lode..');
        END;
END;

---------------- DEMONSTRACIA procedury 1 ---------
BEGIN
    lode_s_vetsou_kapacitou_nez(10);
END;

---------- Procedura 2 --------
-- Vypis informacii o vztahu piratov a lodi
CREATE OR REPLACE PROCEDURE rozirene_informace_lodi
AS
    CURSOR lod_cursor IS SELECT *
                         FROM Lod;
    zkoumana_lod   Lod%ROWTYPE;
    nacteny_pirat  Pirat%ROWTYPE;
    zadna_lod      BOOLEAN;
    nikdo_neveli   BOOLEAN;
    nikdo_neplavi  BOOLEAN;
    CURSOR veleni_cursor IS SELECT *
                            FROM Pirat_veli_lod;
    nactene_veleni Pirat_veli_lod%ROWTYPE;
    CURSOR Pirat_cursor IS SELECT *
                           FROM Pirat;
BEGIN
    DBMS_OUTPUT.ENABLE(buffer_size => NULL);
    zadna_lod := true;
    OPEN lod_cursor;
    LOOP
        FETCH lod_cursor INTO zkoumana_lod;
        EXIT WHEN lod_cursor%notfound;
        nikdo_neplavi := true;
        nikdo_neveli := true;
        zadna_lod := FALSE;
        DBMS_OUTPUT.PUT_LINE('=======================');
        DBMS_OUTPUT.PUT_LINE('ID lode: ' || zkoumana_lod.id || ' typ: ' || zkoumana_lod.typ);
        DBMS_OUTPUT.PUT('Majitel: ');
        IF zkoumana_lod.patri IS NOT NULL THEN
            SELECT * INTO nacteny_pirat FROM Pirat WHERE (id = zkoumana_lod.patri);
            DBMS_OUTPUT.PUT('ID: ' || nacteny_pirat.id || ' prezdivka: ' || nacteny_pirat.prezdivka);
        ELSE
            DBMS_OUTPUT.PUT('nikdo');
        END IF;
        DBMS_OUTPUT.PUT_LINE('');

        DBMS_OUTPUT.PUT_LINE('Na lodi veli: ');
        OPEN veleni_cursor;
        LOOP
            FETCH veleni_cursor INTO nactene_veleni;
            EXIT WHEN veleni_cursor%NOTFOUND;
            IF nactene_veleni.id_lod = zkoumana_lod.id THEN
                nikdo_neveli := FALSE;
                SELECT * INTO nacteny_pirat FROM Pirat WHERE (id = nactene_veleni.id_pirat);
                DBMS_OUTPUT.PUT_LINE('ID: ' || nacteny_pirat.id || ' prezdivka: ' || nacteny_pirat.prezdivka);
            END IF;
        END LOOP;
        CLOSE veleni_cursor;
        IF nikdo_neveli THEN
            DBMS_OUTPUT.PUT_LINE('nikdo');
        END IF;
        DBMS_OUTPUT.PUT_LINE('Na lodi se plavi: ');
        OPEN Pirat_cursor;
        LOOP
            FETCH Pirat_cursor INTO nacteny_pirat;
            EXIT WHEN Pirat_cursor%NOTFOUND;
            IF nacteny_pirat.plavi_se_na = zkoumana_lod.id THEN
                nikdo_neplavi := FALSE;
                DBMS_OUTPUT.PUT_LINE('ID: ' || nacteny_pirat.id || ' prezdivka: ' || nacteny_pirat.prezdivka);
            END IF;
        END LOOP;
        CLOSE Pirat_cursor;
        if nikdo_neplavi THEN
            DBMS_OUTPUT.PUT_LINE('nikdo');
        END IF;
    END LOOP;
    CLOSE lod_cursor;
    IF zadna_lod THEN
        DBMS_OUTPUT.PUT_LINE('Neexistuji zadne lode k prohledani.');
    END IF;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        BEGIN
            DBMS_OUTPUT.PUT_LINE('Nejsou data k prohledani.');
        END;
END;

---------------- DEMONSTRACIA procedury 2 ---------
BEGIN
    rozirene_informace_lodi();
END;

-------------------------------------------------------------------------------
------------------------ EXPLAIN PLAN -----------------------------------------
-------------------------------------------------------------------------------

-- Ktore lode s vyrazom "viking" v typu lodi bojovali v jednej a viac bitvach? (bez indexu)
EXPLAIN PLAN FOR
SELECT Lod.id                 as id_lodi,
       typ                    as typ_lodi,
       COUNT(UNIQUE id_bitva) as pocet_bitev
FROM Lod
         JOIN Lod_bojovala_v_bitva Lbvb on Lod.id = Lbvb.id_lod
WHERE (Lod.typ LIKE '%viking%')
GROUP BY Lod.id, typ
HAVING COUNT(UNIQUE id_bitva) > 0
ORDER BY Lod.id;
-- viking_lode_bez_indexu
SELECT *
FROM TABLE (DBMS_XPLAN.DISPLAY);

-- Ktore lode s vyrazom "viking" v typu lodi bojovali v jednej a viac bitvach? (s indexom)
CREATE INDEX bitva_id_lod_index ON Lod_bojovala_v_bitva(id_lod);
EXPLAIN PLAN FOR
SELECT Lod.id                 as id_lodi,
       typ                    as typ_lodi,
       COUNT(UNIQUE id_bitva) as pocet_bitev
FROM Lod
         JOIN Lod_bojovala_v_bitva Lbvb on Lod.id = Lbvb.id_lod
WHERE (Lod.typ LIKE '%viking%')
GROUP BY Lod.id, typ
HAVING COUNT(UNIQUE id_bitva) > 0
ORDER BY Lod.id;
-- viking_lode_s_indexom
SELECT *
FROM TABLE (DBMS_XPLAN.DISPLAY);

----------------------------------------------------------------------------------------------------------
------------------------ PRISTUPOVE PRAVA PRE DRUHEHO CLENA TYMU -----------------------------------------
----------------------------------------------------------------------------------------------------------

-- PRE UZIVATELA XBOBOL00 ----------------
-- tabulky
GRANT ALL ON Aliance TO XBOBOL00;
GRANT ALL ON Kapitan TO XBOBOL00;
GRANT ALL ON Lod TO XBOBOL00;
GRANT ALL ON Pirat TO XBOBOL00;
GRANT ALL ON Posadka TO XBOBOL00;
GRANT ALL ON Pristav TO XBOBOL00;
GRANT ALL ON Radovy_pirat TO XBOBOL00;
GRANT ALL ON Bitva TO XBOBOL00;
GRANT ALL ON Pirat_veli_lod TO XBOBOL00;
GRANT ALL ON Lod_bojovala_v_bitva TO XBOBOL00;
-- procedury
GRANT EXECUTE ON lode_s_vetsou_kapacitou_nez TO XBOBOL00;
GRANT EXECUTE ON rozirene_informace_lodi TO XBOBOL00;

/*
-- PRE UZIVATELA XSYSEL09 ----------------
-- tabulky
GRANT ALL ON Aliance TO XSYSEL09;
GRANT ALL ON Kapitan TO XSYSEL09;
GRANT ALL ON Lod TO XSYSEL09;
GRANT ALL ON Pirat TO XSYSEL09;
GRANT ALL ON Posadka TO XSYSEL09;
GRANT ALL ON Pristav TO XSYSEL09;
GRANT ALL ON Radovy_pirat TO XSYSEL09;
GRANT ALL ON Bitva TO XSYSEL09;
GRANT ALL ON Pirat_veli_lod TO XSYSEL09;
GRANT ALL ON Lod_bojovala_v_bitva TO XSYSEL09;
-- procedury
GRANT EXECUTE ON lode_s_vetsou_kapacitou_nez TO XSYSEL09;
GRANT EXECUTE ON rozirene_informace_lodi TO XSYSEL09;
 */

-----------------------------------------------------------------------------------------
------------------------ MATERIALIZOVANY POHLED -----------------------------------------
-----------------------------------------------------------------------------------------

-- Spusta uzivatel: XBOBOL00, tabulky definovane uzivatelom: XSYSEL09
-- Materializovany pohlad na vsetkych piratov a ich barva vousu
CREATE MATERIALIZED VIEW barva_vousu_piratu
CACHE
BUILD IMMEDIATE
REFRESH ON COMMIT AS
    SELECT XSYSEL09.PIRAT.ID AS ID_PIRATA,
           XSYSEL09.PIRAT.PREZDIVKA AS PREZDIVKA_PIRATA,
           XSYSEL09.PIRAT.BARVA_VOUSU AS BARVA_VOUSU
    FROM XSYSEL09.PIRAT;

---------------- DEMONSTRACIA materialiuovany pohled ---------
INSERT INTO Pirat (jmeno, prezdivka, vek, barva_vousu, cas_sluzby, charakteristiky, plavi_se_na)
VALUES (NULL, 'Pravý', 18, 'blond', NULL, 'nosí kilt', NULL);
-- Materializovany pohlad pred commitom
SELECT * from barva_vousu_piratu;
COMMIT;
-- Materializovany pohlad po commit
SELECT * from barva_vousu_piratu;