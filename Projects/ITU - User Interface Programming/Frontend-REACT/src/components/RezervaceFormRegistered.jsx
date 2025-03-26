/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file RezervaceFormRegistered.jsx
 */

import React, {useState} from "react";
import { Post } from "../static/Loaders";

/**
 * Used to create new rezervation for user
 * @param {*} details registration details
 * @param {*} id name of conferention
 * @param {*} setTransakce setter of variable transakce
 * @returns {*} {error, dataToReturn}
 */
async function Rezervace(details, id, setTransakce){

    if(details.Pocet_vstupenek < 1)
        return;

    let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+id+'/novaRezervace', null, JSON.stringify(details));

    if(!error){
        setTransakce(dataToReturn);
    }
    return {error, dataToReturn}
}

/**
 * Form for used for buying tickets for logged in users
 * @param {*} Update Update fnc
 * @param {*} setErr setter for variable error
 * @param {*} konfData data about conferention
 * @returns 
 */
function RezervaceFormRegistered({Update, setErr, konfData}) {

    const [transakce, setTransakce] = useState(null);

    const [details, setDetails] = useState({
        Konfenerce: "",  Uzivatel: "", Jmeno: "", Prijmeni: "",
        Email: "", Pocet_vstupenek: "", Celkova_cena: "", Stav: ""
    });

    const _Rezervace = async () =>{
        let {error, dataToReturn: transakce} = await Rezervace(details, konfData.Nazev, setTransakce)
    }

    let form = (
        <form onSubmit="" class="needs-validation" novalidate="">
        <div className="form-inner">
            <h1 class="h3 mb-3 fw-normal">Rezervace vstupenek</h1>

                <div class="row g-3">
                    <div class="col-12">
                        Konference: {konfData.Nazev}
                        <br/>
                        Cena vstupenky: {konfData.Cena_vstup}
                        <br/>
                        Zbývající kapacita: {konfData.ZbyvajiciKapacita ? konfData.ZbyvajiciKapacita : konfData.Kapacita }
                        <br/>
                        <br/>
                    </div>

                    <div class="col-12">
                        <label for="Pocet_vstupenek" class="form-label">Počet vstupenek</label>
                        <input type="number" class="form-control" id="Pocet vstupenek" required=""
                        onChange={e => setDetails({...details, Pocet_vstupenek: e.target.value > 0 ? e.target.value : 0})} value={details.Pocet_vstupenek}/>
                    </div>

                </div>

                <br/>

                <button class="w-10 btn btn-lg btn-primary" type="button" onClick={_Rezervace}>Potvrdit rezervaci</button>
            </div>
        </form>
    )

    let dokoncenaMsg = transakce ? (
        <div class="fa fa-transgender" aria-hidden="true" >
            id transakcie: {transakce.ID} <br/>
            Stav svojej transakcie môžte sledovať cez rezervace <br/>
            stav svojej trasakcie môžte sledovať aj cez svoj profil
        </div>
    ) : null;

return (
        transakce ?
        dokoncenaMsg : 
        form
  );
}

export default RezervaceFormRegistered;
