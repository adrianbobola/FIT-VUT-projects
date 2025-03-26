/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file KonferenceDetailsEditable.jsx
 */
import React, {useState} from 'react';
import { Put } from '../../static/Loaders';

/**
 * Updates conference details
 * @param details data to put
 */
const UpravKonf = async details => {

    let {dataToReturn, pending, error} = await Put('http://ituprojekt.fun:8000/konference/'+details.Nazev+'/upravit', null, JSON.stringify(details));

    if(error) {
        //Do something
    }
    else{
        //OK
    }
}

/**
 * Details of conference - editable
 * @param {*} data data to use
 * @returns Html
 */
function KonferenceDetailsEditable({data}){

    const [opened, setOpened] = useState(false);

    const [details, setDetails] = useState({
        Nazev: data.Nazev, Popis: data.Popis, Obor: data.Obor, Zeme: data.Zeme, 
        Mesto: data.Mesto, Misto: data.Misto ,
        Zacatek_datum: data.Zacatek_datum, Konec_datum: null, Zacatek_cas: data.Zacatek_cas, Konec_cas: data.Konec_cas,
        Poplatek: data.Poplatek, Cena_vstup: data.Cena_vstup, Kapacita: data.Kapacita, Doplnujici_udaje: data.Doplnujici_udaje
    });

    const submitHandler = e => {
        e.preventDefault();

        console.log(details)

        if(!details.Nazev || !details.Obor || !details.Zeme || !details.Mesto || !details.Misto
            || !details.Zacatek_datum || !details.Zacatek_cas || !details.Konec_cas
            || !details.Poplatek || !details.Cena_vstup || !details.Kapacita)
        {

        }
        else{
            UpravKonf(details)
        }
    }

    let form = (
        <form onSubmit={submitHandler} class="needs-validation" novalidate="">
        <div className="form-inner">
            <h1 class="h3 mb-3 fw-normal">Nová konference</h1>

                <div class="row g-3">
                    <div class="col-12">
                        <label for="Nazev" class="form-label">Název <span class="text-muted">(Nemuže být změněn později)</span></label>
                        <input type="text" class="form-control" id="Nazev"
                        onChange="" value={details.Nazev}/>
                    </div>

                    <div class="col-12">
                        <label for="Popis" class="form-label">Popis</label>
                        <input type="text" class="form-control" id="Popis"
                        onChange={e => setDetails({...details, Popis: e.target.value})} value={details.Popis}/>
                    </div>

                    <div class="col-12">
                        <label for="Obor" class="form-label">Obor</label>
                        <input type="text" class="form-control" id="Obor"
                        onChange={e => setDetails({...details, Obor: e.target.value})} value={details.Obor}/>
                    </div>

                    <div class="col-12">
                        <label for="Zeme" class="form-label">Zeme</label>
                        <input type="Zeme" class="form-control" id="Zeme"
                        onChange={e => setDetails({...details, Zeme: e.target.value})} value={details.Zeme}/>
                        <div class="invalid-feedback">
                            Zadejte prosím validní Zemi
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="Mesto" class="form-label">Mesto</label>
                        <input type="Mesto" class="form-control" id="Mesto"
                        onChange={e => setDetails({...details, Mesto: e.target.value})} value={details.Mesto}/>
                    </div>


                    <div class="col-12">
                        <label for="Misto" class="form-label">Místo</label>
                        <input type="Misto" class="form-control" id="Misto"
                        onChange={e => setDetails({...details, Misto: e.target.value})} value={details.Misto}/>
                    </div>

                    <div class="col-12">
                        <label class="form-label">Start</label>
                        <input type="date" class="form-control" id="Zacatek_datum"
                        onChange={e => setDetails({...details, Zacatek_datum: e.target.value})} value={details.Zacatek_datum}/>
                        <input type="time" class="form-control" id="Zacatek_cas"
                        onChange={e => setDetails({...details, Zacatek_cas: e.target.value})} value={details.Zacatek_cas}/>
                    </div>

                    <div class="col-12">
                        <label class="form-label">End</label>
                        <input type="time" class="form-control" id="Konec_cas"
                        onChange={e => setDetails({...details, Konec_cas: e.target.value})} value={details.Konec_cas}/>
                    </div>

                    <div class="col-12">
                        <label for="Poplatek" class="form-label">Poplatek</label>
                        <input type="number" class="form-control" id="Poplatek"
                        onChange={e => setDetails({...details, Poplatek: e.target.value > 0 ? e.target.value : 0})} value={details.Poplatek}/>
                    </div>

                    <div class="col-12">
                        <label for="Cena_vstup" class="form-label">Cena vstupenky</label>
                        <input type="number" class="form-control" id="Cena_vstup"
                        onChange={e => setDetails({...details, Cena_vstup: e.target.value > 0 ? e.target.value : 0})} value={details.Cena_vstup}/>
                    </div>

                    <div class="col-12">
                        <label for="Kapacita" class="form-label">Kapacita</label>
                        <input type="number" class="form-control" id="Kapacita"
                        onChange={e => setDetails({...details, Kapacita: e.target.value > 0 ? e.target.value : 0})} value={details.Kapacita}/>
                    </div>

                    <div class="col-12">
                        <label for="Doplnujici_udaje" class="form-label">Doplňující údaje</label>
                        <input type="text" class="form-control" id="Doplnujici_udaje"
                        onChange={e => setDetails({...details, Doplnujici_udaje: e.target.value})} value={details.Doplnujici_udaje}/>
                    </div>
                </div>

                <br/>

                <button class="w-100 btn btn-lg btn-primary" type="submit">Potvrdit změny</button>

            </div>
        </form>
    )

return (
    <div>
            <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
                    onClick={(() => setOpened(!opened))}>
                <i class="nc-icon nc-stre-up"></i>
                {opened ? "Skrýt" : "Zobrazit"}
            </button>
            {opened && form}
    </div>  
  );

}

export default KonferenceDetailsEditable;