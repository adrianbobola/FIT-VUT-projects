/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file KonferenceDetailsReadOnly.jsx
 */
import React, {useState} from 'react';

/**
 * Details of conference - read only
 * @param {*} data data to use
 * @returns Html
 */
function KonferenceDetailsReadOnly({data}){

    const [opened, setOpened] = useState(false);

    let card;

    card = (
            <div class="bg-light px-3">
                <p>Popis: {data.Popis}</p>
                <p>Obor: {data.Obor}</p>
                <p>Zeme: {data.Zeme}</p>
                <p>Mesto: {data.Mesto}</p>
                <p>Misto: {data.Misto}</p>
                <p>Zacatek: {data.Zacatek_datum}, {data.Zacatek_cas}</p>
                <p>Konec: {data.Konec_cas}</p>
                <p>Poplatek: {data.Poplatek}</p>
                <p>Vstupné: {data.Cena_vstup}</p>
                <p>Kapacita: {data.Kapacita}</p>
                <p>Další údaje: {data.Doplnujici_udaje}</p>
            </div>
    )

    return(

        <div>
                <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
                        onClick={(() => setOpened(!opened))}>
                    <i class="nc-icon nc-stre-up"></i>
                    {opened ? "Skrýt" : "Zobrazit"}
                </button>
                {opened && card}
        </div>

    );

}

export default KonferenceDetailsReadOnly;