/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file RezervaceFormNotRegistered.jsx
 */

import React, {useState} from "react";
import { Post } from "../static/Loaders";
import { useLocation} from "react-router-dom"

/**
 * Used to create new rezervation for non-registered user without registration
 * @param {*} details registration details
 * @param {*} id name of conferention
 * @param {*} setTransakce setter of variable transakce
 * @returns {*} {error, dataToReturn}
 */
async function Rezervace(details, id, setTransakce){

    if(details.Pocet_vstupenek < 1 || !details.Jmeno || !details.Prijmeni)
        return;

    let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+id+'/novaRezervace/nereg', null, JSON.stringify(details));

    if(!error){
        setTransakce(dataToReturn);
    }
    return {error, dataToReturn}
}

/**
 * Used to create new rezervation for non-registered user with registration
 * @param {*} details registration details
 * @param {*} id name of conferention
 * @param {*} setTransakce setter of variable transakce
 * @returns {*} {error, dataToReturn}
 */
async function RezervaceARegistrovat(details, id, setTransakce){

    if(details.Pocet_vstupenek < 1 || !details.Jmeno || !details.Prijmeni || !details.Heslo)
        return;

    let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+id+'/novaRezervace/reg', null, JSON.stringify(details));

    if(!error){
        setTransakce(dataToReturn);
    }
    return {error, dataToReturn}
}

/**
 * Form for used for buying tickets for non-registered/ not logged in users
 * @param {*} Update Update fnc
 * @param {*} setErr setter for variable error
 * @param {*} konfData data about conferention
 * @returns 
 */
function RezervaceFormNotRegistered({Update, setErr, konfData}) {

    const [transakce, setTransakce] = useState(null);

    const [details, setDetails] = useState({
        Konfenerce: "",  Uzivatel: "", Jmeno: "", Prijmeni: "",
        Email: "", Pocet_vstupenek: "", Celkova_cena: "", Stav: ""
    });

    const _Rezervace = async () =>{
        let {error, dataToReturn: transakce} = await Rezervace(details, konfData.Nazev, setTransakce)
    }

    const _RezervaceARegistrovat = async () =>{
        let {error, dataToReturn: transakce} = await RezervaceARegistrovat(details, konfData.Nazev, setTransakce)
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

                    <div class="col-12">
                        <label for="Jmeno" class="form-label">Jmeno </label>
                        <input type="text" class="form-control" id="Jmeno" required=""
                        onChange={e => setDetails({...details, Jmeno: e.target.value})} value={details.Jmeno}/>
                    </div>

                    <div class="col-12">
                        <label for="Prijmeni" class="form-label">Prijmeni </label>
                        <input type="text" class="form-control" id="Prijmeni" required=""
                        onChange={e => setDetails({...details, Prijmeni: e.target.value})} value={details.Prijmeni}/>
                    </div>

                    <div class="col-12">
                        <label for="Email" class="form-label">Email </label>
                        <input type="email" class="form-control" id="Email"
                        onChange={e => setDetails({...details, Email: e.target.value})} value={details.Email}/>
                    </div>

                    <div class="col-12">
                        <label for="Heslo" class="form-label">Heslo <span class="text-muted">(Jenom v případe registrace)</span> </label>
                        <input type="password" class="form-control" id="Heslo"
                        onChange={e => setDetails({...details, Heslo: e.target.value})} value={details.Heslo}/>
                    </div>

                </div>

                <br/>

                <button class="w-10 btn btn-lg btn-primary" type="button" onClick={_RezervaceARegistrovat}>Potvrdit a registrovat</button>
                <button class="w-10 btn btn-lg btn-primary" type="button" onClick={_Rezervace}>Potvrdit bez registrace</button>
            </div>
        </form>
    )

    let dokoncenaMsg = transakce ? (
        <div class="fa fa-transgender" aria-hidden="true" >
            Uchovajte si nasledujúce údaje:  <br/>
            id transakcie: {transakce.ID} <br/>
            Stav svojej transakcie môžte sledovať cez rezervace <br/>
            Ak ste sa registrovali, stav svojej trasakcie môžte sledovať aj cez svoj profil
        </div>
    ) : null;

return (
        transakce ?
        dokoncenaMsg : 
        form
  );
}

export default RezervaceFormNotRegistered;
