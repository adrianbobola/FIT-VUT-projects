/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file RegistrationForm.jsx
 */
import React, { useState } from 'react'

/**
 * returns Registration form
 * @param Registration login fnc
 * @param error errorToDisplay
 * @returns HTML
 */
function RegistrationForm({Registration, error}) {

    const [details, setDetails] = useState({
        Jmeno: "", Prijmeni: "", Titul: "", Email: "", TelCislo: null, 
        Heslo: "", Organizace: "", Obor: "", Zeme: "",
        Datum_narozeni: null
    });

    const submitHandler = e => {
        e.preventDefault();

        /* if(details.Datum_narozeni === "")
            details.Datum_narozeni = null; */

        Registration(details);
    }

    return (
        <form onSubmit={submitHandler} class="needs-validation" novalidate="">
            <div className="form-inner">
            <h1 class="h3 mb-3 fw-normal">Registrace</h1>

                <p style={{color: 'red'}}>{error}</p>
                    
                <div class="row g-3">
                    <div class="col-sm-6">
                        <label for="Jmeno" class="form-label">Jméno</label>
                        <input type="text" class="form-control" id="Jmeno" placeholder="" required=""
                        onChange={e => setDetails({...details, Jmeno: e.target.value})} value={details.Jmeno}/>
                        <div class="invalid-feedback">
                            Jméno není validní.
                        </div>
                    </div>

                    <div class="col-sm-6">
                        <label for="Prijmeni" class="form-label">Příjmení</label>
                        <input type="text" class="form-control" id="Prijmeni" placeholder="" required=""
                        onChange={e => setDetails({...details, Prijmeni: e.target.value})} value={details.Prijmeni}/>
                        <div class="invalid-feedback">
                            Příjmení není validní.
                        </div>
                    </div>

                    <div class="col-sm-6">
                        <label for="Titul" class="form-label">Titul</label>
                        <br />
                        <select class="form-select" id="Titul" 
                        onChange={e => setDetails({...details, Titul: e.target.value})} value={details.Titul}>
                            <option value="">Vybrat...</option>
                            <option>-</option>
                            <option>Bc.</option>
                            <option>Ing.</option>
                            <option>Mgr.</option>
                            <option>Phd.</option>
                        </select>
                    </div>

                    <div class="col-12">
                        <label for="Heslo" class="form-label">Heslo</label>
                        <input type="password" class="form-control" id="Heslo" required=""
                        onChange={e => setDetails({...details, Heslo: e.target.value})} value={details.Heslo}/>
                        <div class="invalid-feedback">
                            Zadejte prosím validní Email
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="Email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="Email" placeholder="smth@example.com" required=""
                        onChange={e => setDetails({...details, Email: e.target.value})} value={details.Email}/>
                        <div class="invalid-feedback">
                            Zadejte prosím validní Email
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="TelCislo" class="form-label">Telefonní číslo<span class="text-muted">(Nepovinné)</span></label>
                        <input type="tel" class="form-control" id="TelCislo" placeholder="+420 xxxx xxx xxx" required=""
                        onChange={e => setDetails({...details, TelCislo: e.target.value})} value={details.TelCislo}/>
                        <div class="invalid-feedback">
                            Zadejte prosím validní telefononní číslo
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="Organizace" class="form-label">Organizace<span class="text-muted">(Nepovinné)</span></label>
                        <input type="text" class="form-control" id="Organizace" placeholder="VUT FIT"
                        onChange={e => setDetails({...details, Organizace: e.target.value})} value={details.Organizace}/>
                        <div class="invalid-feedback">
                            Zadejte existující organizaci
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="Obor" class="form-label">Obor<span class="text-muted">(Nepovinné)</span></label>
                        <input type="text" class="form-control" id="Obor" placeholder="informatika"
                        onChange={e => setDetails({...details, Obor: e.target.value})} value={details.Obor}/>
                        <div class="invalid-feedback">
                            Zadejte platnou organizaci
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="zeme" class="form-label">Země<span class="text-muted">(Nepovinné)</span></label>
                        <input type="text" class="form-control" id="zeme" placeholder="Česko"
                        onChange={e => setDetails({...details, Zeme: e.target.value})} value={details.Zeme}/>
                        <div class="invalid-feedback">
                            Zadejte existujíci zemi
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="Datum_narozeni" class="form-label">Datum narození<span class="text-muted">(Nepovinné)</span></label>
                        <input type="date" class="form-control" id="Datum_narozeni" placeholder=""
                        onChange={e => setDetails({...details, Datum_narozeni: e.target.value})} value={details.Datum_narozeni}/>
                        <div class="invalid-feedback">
                            Zadejte validní datum narození
                        </div>
                    </div>
                </div>

                <br/>

                <button class="w-100 btn btn-lg btn-primary" type="submit">Zaregistrovat se</button>

            </div>
        </form>
    )
}

export default RegistrationForm;