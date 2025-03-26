Cílem je vytvořit terminál s klávesnicí a dvěma ledkami (otevřeno / zavřeno).
Desku ESP32 s periferiemi si vyzvednete u vedoucího (před tím vám pošle e-mail)
Požadavky na výslednou aplikaci
ESP32 budete programovat pomocí rozhraní IDF (ne tedy Arduino - při použití Arduino knihoven jste hodně odstíněni od práce s periferiemi a od FreeRTOSu, proto by mohlo být za toto zjednodušení sníženo bodové ohodnocení)
K desce bude připojená maticová klávesnice a dvě LED diody - zelená a červená. Po zadání správného přístupového kódu se na chvíli otevře (rozsvítí zelená), pak se zase přejde do zamklého (červeného) stavu.
Přístupový kód bude nastavitelný - po zadání speciálního kódu (např. #1234*5678) se změní kód z 1234 na 5678.
Zamyslete se nad ovládáním a nad rozumnou signalizací i za použití dvou LED
Vycházejte z dokumentace IDF a ukázek.
Vytvořte přehlednou dokumentaci k přípravě, způsobu realizace, k funkčnosti a vlastnostem řešení projektu.