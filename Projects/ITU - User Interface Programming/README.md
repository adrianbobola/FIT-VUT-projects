Zadanie:
Konference: správa událostí, prezentací a účastníků

Úkolem zadání je vytvořit informační systém pro tvorbu událostí a správu účastníků konferencí obsahující prezentace vybraných přednášejících. Každá konference má nějaké označení, pomocí kterého ji její návštěvníci budou moci vhodně odlišit a další vhodné atributy (popis, žánr/oblast zájmu, místo, apod.). Konference se koná v nějaký časový interval, účast stojí nějakou cenu a má nějakou kapacitu návštěvníků. Dále obsahuje libovolný počet místností, v kterých vystoupí dle stanoveného rozpisu přednášející přijatých prezentací. Každá prezentace je charakterizována popisem (název, přednášející, popis, případně tagy, fotka/logo/poster apod...) a má přesně vymezený čas a místnost na konferenci. Uživatelé budou moci informační systém použít jak pro vkládání a správu konferencí, místností, tak pro podávání a schvalování prezentací a rezervaci/nákup vstupenek na konference - a to následujícím způsobem:
administrátor

spravuje uživatele

má rovněž práva všech následujících rolí

registrovaný uživatel

zakládá konference - stane se pořadatelem konference

spravuje místnosti a obsah konference

schvaluje přednášející na konference, vytváří časový rozpis přednášek v místnostech (časové kolize ošetřete)

spravuje rezervace návštěvníků, po úhradě vstupného potvrdí rezervaci a případně vydá vstupenky (pokud je hrazeno na místě)

registruje své příspěvky na konference (zasílá návrh prezentace - postačí ve formě textu) - stane se přednášejícím na konferenci

vidí uživatelsky přívětivý rozpis svých přednášek

(pořadatel se může přihlásit na svoji konferenci jako přednášející)

rezervuje 1 až N vstupenek (zvolte vhodné omezení - např. maximální množství, úhrada v daném intervalu - kontroluje a případně ruší pořadatel) - stane se návštěvníkem konference

sleduje stav jeho rezervací (provedení úhrady)

vidí uživatelsky přívětivý rozpis přednášek konference, může si vytvářet osobní rozvrh

neregistrovaný

vidí dostupné konference a jejich obsah

má možnost vhodně vidět, které konference jsou vyprodané (v případě souběžně prováděných rezervací více uživateli a překročení limitu míst je pomalejší uživatel vhodně upozorněn, že jeho registrace nebyla provedena)

může provést rezervaci 1 až N vstupenek bez registrace: vyžadujte vhodné údaje (má možnost dokončit registraci a stát se návštěvníkem konference)
------------------------------------------------------------------------------------------------------------------------------------------------

Pre správne fungovanie aplikácie je potrebné mať na serveri nainštalovaný Apache HTTP server, MySQL server (používali sme MariaDB), PHP, inštalačný balík pre Node.js aplikácie (pre zobrazenie aktuálnej verzie spustíme príkaz "node -v"), webové rozhranie phpMyAdmin
- Súbory zo zložky "src" nahráme na Apache HTTP server (štandardne /var/www/html)
FRONTEND:
- Prejdeme do zložky "frontend" kde pomocou príkazu "sudo npm install" spustíme stiahnutie potrebných závislostí pre React aplikáciu (závislosti sa stiahnú do zložky "node_modules")
- Po úspešnom nainštalovaní všetkých závislosti spustíme vytvorenie HTML súboru príkazom "sudo npm run build"
- Po úspešnom vytvorení obsahu stránok vznikne zložka "build" v zložke frontend
- Následne stačí obsah zložky "build" prekopírovať do adresáru webového priestoru (štandardne /var/www/html)
- Na záver je potebné nastaviť prístupové práva (najmä pre novovytvorenú zložku /upload/files/) pre možnosť zápisu (odporúčam použiť príkaz "chmod -R 755 /var/www/html/frontend/")
- Kód je aktuálne nasadený na doméne ituprojekt.fun. Pre použitie lokálne spusteného servera je vo frontendových súboroch potrebné hromadne zmeniť reťazec "ituprojekt.fun" na adresu servra so spusteným backendom.

DATABÁZA:
- Pre vytvorenie databázy môžeme použiť rozhranie phpMyAdmin
- Vytvoríme novú databázu s názvom "ituproject" - kódovanie nastavíme na "UTF-8_CZECH"
- zvolíme "import zo súboru" a vyberieme odovzdaný súbor "/databaze/db.sql", tým sa nám vytvoria potrebné tabuľky v databáze
- názov databázy je taktiež možné zmeniť v súbore backendu "/config/database.js" (predvolená hodnota "ituproject", host = "localhost")
- prihlasovacie údaje k db je potrebné pridať aj do súboru ".env" ako napr. "DB_NICK" a "DB_PWD". (Tento súbor obsahuje pod názvom "SECRET" tiež tajný kľúč slúžiaci na overenie podpisu tokenu.)
- súbor ".env" umiestnime do koreňového adresára backendu (súbor: "/backend/.env")

BACKEND:
- Prejdeme do zložky "backend" kde pomocou príkazu "sudo npm install" spustíme stiahnutie potrebných závislostí pre Express.js aplikáciu (závislosti sa stiahnú do zložky "node_modules")
- Po úspešnom nainštalovaní všetkých závislosti spustíme BE server pomocou príkazu "npm run start"
Po úspešnom absolvovaní všetkých krokov a spustenom procese pre backendovú aplikáciu je aplikácia plne funkčná a môžeme ju spustiť pomocou adresy nášho servera cez webový prehliadač.