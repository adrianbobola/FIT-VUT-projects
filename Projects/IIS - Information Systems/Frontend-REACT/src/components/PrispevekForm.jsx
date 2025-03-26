/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file PrispevekForm.jsx
 */
import React, {useState} from "react";

/**
 * returns Registration form
 * @param Update Update function
 * @param setErr errorToDisplay
 * @returns HTML
 */
function PrispevekForm({Update, setErr}) {    

    const [details, setDetails] = useState({
        Nazev: "", Konference: "", Uzivatel: "", Popis: "",
        Tagy: "", Grafika: "" ,
        Soubor: "", Mistnost: "", Zacatek_cas: null, Konec_cas: null,
        Datum: null, poznamkyPoradatele: ""
    });

    const submitHandler = e => {
        e.preventDefault();

        console.log(details)

        if(!details.Nazev )
        {
            setErr("Zadejte název prezentace")
        }
        else{
            Update(details)
        }
    }

    let form = (
        <form onSubmit={submitHandler} class="needs-validation" novalidate="">
        <div className="form-inner">
            <h1 class="h3 mb-3 fw-normal">Nový prispevek do konference</h1>

                <div class="row g-3">
                    <div class="col-12">
                        <label for="Nazev" class="form-label">Název </label>
                        <input type="text" class="form-control" id="Nazev"
                        onChange={e => setDetails({...details, Nazev: e.target.value})} value={details.Nazev}/>
                    </div>

                    <div class="col-12">
                        <label for="Popis" class="form-label">Popis </label>
                        <input type="text" class="form-control" id="Popis"
                        onChange={e => setDetails({...details, Popis: e.target.value})} value={details.Popis}/>
                    </div>

                    <div class="col-12">
                        <label for="Tagy" class="form-label">Tagy </label>
                        <input type="text" class="form-control" id="Tagy"
                        onChange={e => setDetails({...details, Tagy: e.target.value})} value={details.Tagy}/>
                    </div>

                    <div class="col-12">
                        <label for="Grafika" class="form-label">Grafika </label>
                        <input type="text" class="form-control" id="Grafika"
                        onChange={e => setDetails({...details, Grafika: e.target.value})} value={details.Grafika}/>
                    </div>

                    <div class="col-12">
                        <label for="Soubor" class="form-label">Soubor </label>
                        <textarea type="text" class="form-control" id="Soubor"
                        onChange={e => setDetails({...details, Soubor: e.target.value})} value={details.Soubor}/>
                    </div>

                </div>

                <br/>

                <button class="w-100 btn btn-lg btn-primary" type="submit">Potvrdit prispevek</button>

            </div>
        </form>
    )

return (
    form
  );
}

export default PrispevekForm;
