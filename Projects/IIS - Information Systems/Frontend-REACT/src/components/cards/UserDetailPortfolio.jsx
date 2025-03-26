/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file UserDetailPortfolio.jsx
 */
import React, { useState, Fragment } from 'react';
import "./MistnostiTable.css";
import ReadRow from "./components/PrezentaceReadRow";
import { useGet } from '../../static/Loaders';

/**
 * Datail of user
 * @param {*} uzivatel user id
 * @returns 
 */
function UserDetailPortfolio({ uzivatel }) {

    const [open, setOpen] = useState(false);
    const [openPrezentace, setOpenPrezentace] = useState(false);

    let details = uzivatel;
    let { data, pending, error } = useGet('http://ituprojekt.fun:8000/uzivatel/' + details.ID + '/prispevky', null)

    let card;
    let cardPrezentace;

    if (open) {
        card = (
            <form onSubmit="" class="needs-validation" novalidate="">
                <div className="form-inner">
                    <h1 class="h3 mb-3 fw-normal">Údaje</h1>

                    <div class="row g-3">
                        <div class="col-sm-6">
                            <label for="name" class="form-label">Jméno</label>
                            <input type="text" class="form-control" id="name"
                                onChange="" value={details.Jmeno} />
                        </div>

                        <div class="col-sm-6">
                            <label for="surname" class="form-label">Příjmení</label>
                            <input type="text" class="form-control" id="surname"
                                onChange="" value={details.Prijmeni} />
                        </div>

                        <div class="col-sm-6">
                            <label for="degree" class="form-label">Titul</label>
                            <br />
                            <select class="form-select" id="degree"
                                onChange="" value={details.Titul ? details.Titul : ""}>
                            </select>
                        </div>

                        <div class="col-12">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email"
                                onChange="" value={details.Email ? details.Email : ""} />
                        </div>

                        <div class="col-12">
                            <label for="telNmb" class="form-label">Telefonní číslo</label>
                            <input type="tel" class="form-control" id="telNmb"
                                onChange="" value={details.TelCislo ? details.TelCislo : ""} />
                            <div class="invalid-feedback">
                                Zadejte prosím validní telefononní číslo
                            </div>
                        </div>

                        <div class="col-12">
                            <label for="organisation" class="form-label">Organizace</label>
                            <input type="text" class="form-control" id="organisation"
                                onChange="" value={details.Organizace ? details.Organizace : ""} />
                        </div>

                        <div class="col-12">
                            <label for="field" class="form-label">Obor</label>
                            <input type="text" class="form-control" id="field"
                                onChange="" value={details.Obor ? details.Obor : ""} />
                        </div>

                        <div class="col-12">
                            <label for="zeme" class="form-label">Země</label>
                            <input type="text" class="form-control" id="zeme"
                                onChange="" value={details.Zeme ? details.Zeme : ""} />
                        </div>

                        <div class="col-12">
                            <label for="birthday" class="form-label">Datum narození</label>
                            <input type="date" class="form-control" id="birthday"
                                onChange="" value={details.Datum_narozeni ? details.Datum_narozeni : ""} />
                        </div>
                    </div>

                    <br />

                </div>
            </form>
        )
    } else {
        card = null;
    }

    /* Zobraz prezentace uzivatele */
    if (openPrezentace) {
        cardPrezentace = (
            <div className="app-container">
                <form onSubmit="">
                    <div class="table-responsive">
                        <h1 class="h3 mb-3 fw-normal">Příspěvky užívatele:</h1>

                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Nazev</th>
                                    <th>Konference</th>
                                    <th>Prednasajuci</th>
                                    <th>Popis</th>
                                    <th>Tagy</th>
                                    <th>Grafika</th>
                                    <th>Soubor</th>
                                    <th>Mistnost</th>
                                    <th>Schavalena</th>
                                    <th>Zacatek cas</th>
                                    <th>Konec cas</th>
                                    <th>Poznamky poradatele</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.map((room) => (
                                    <Fragment>
                                        <ReadRow data={room} />
                                    </Fragment>
                                ))}
                            </tbody>
                        </table>

                    </div>
                </form>
            </div>
        )
    } else {
        cardPrezentace = null;
    }

    return (
        <div class="card">
            <div class="card-header card-header-flex">
                <h3 class="card-title text-bold"> {details.ID}: {details.Email} </h3>
                <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
                    onClick={() => setOpen(!open)}>
                    <i class="nc-icon nc-stre-up"></i>
                    {open ? "Skrýt" : "Zobrazit"}
                </button>

                <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
                    onClick={() => setOpenPrezentace(!openPrezentace)}>
                    <i class="nc-icon nc-stre-up"></i>
                    {openPrezentace ? "Skrýt příspěvky" : "Zobrazit příspěvky"}
                </button>
                {card}
                {cardPrezentace}
            </div>

        </div>
    )

}

export default UserDetailPortfolio;