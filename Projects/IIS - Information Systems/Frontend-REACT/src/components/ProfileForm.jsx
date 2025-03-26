/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file ProfileForm.jsx
 */
import React, { useState } from 'react'

/**
 * Profile form
 * @param {*} Update function to call when submitting update of profile
 * @param {*} userInfo user details
 * @param {*} adminUpdate permit admin role
 * @returns 
 */
function ProfileForm({ Update, userInfo, adminUpdate }) {

    const [role, setRole] = useState('uzivatel');
    const [details, setDetails] = useState({
        ID: userInfo.ID, name: userInfo.Jmeno, surname: userInfo.Prijmeni, degree: userInfo.Titul, email: userInfo.Email,
        telNmb: userInfo.TelCislo, organisation: userInfo.Organizace, field: userInfo.Obor,
        country: userInfo.Zeme, birthday: userInfo.Datum_narozeni
    });

    const submitHandler = e => {
        e.preventDefault();

        if (details.name !== "" && details.surname !== "") {
            Update(details, role);
            window.location.reload(false);
        }
    }

    return (
        <form onSubmit={submitHandler} class="needs-validation" novalidate="">
            <div className="form-inner">
                <h1 class="h3 mb-3 fw-normal">Údaje</h1>

                <div class="row g-3">
                    <div class="col-sm-6">
                        <label for="name" class="form-label">Jméno</label>
                        <input type="text" class="form-control" id="name"
                            onChange={e => setDetails({ ...details, name: e.target.value })} value={details.name} />
                        <div class="invalid-feedback">
                            Jméno není validní.
                        </div>
                    </div>

                    <div class="col-sm-6">
                        <label for="surname" class="form-label">Příjmení</label>
                        <input type="text" class="form-control" id="surname"
                            onChange={e => setDetails({ ...details, surname: e.target.value })} value={details.surname} />
                        <div class="invalid-feedback">
                            Příjmení není validní.
                        </div>
                    </div>

                    <div class="col-sm-6">
                        <label for="degree" class="form-label">Titul</label>
                        <br />
                        <select class="form-select" id="degree"
                            onChange={e => setDetails({ ...details, degree: e.target.value })} value={details.degree}>
                            <option value="">Vybrat...</option>
                            <option>-</option>
                            <option>Bc.</option>
                            <option>Ing.</option>
                            <option>Mgr.</option>
                            <option>Phd.</option>
                        </select>

                    </div>

                    {adminUpdate && (
                        <div className="col-12">
                            <label htmlFor="role" className="form-label">Role</label>
                            <select name="role" className="form-control" id="role"
                                onChange={e => setRole(e.target.value)} value={role}>
                                <option value="uzivatel">Uzivatel</option>
                                <option value="administrator">Administrator</option>
                            </select>
                            <div className="invalid-feedback">
                                Zadejte prosím validní roli
                            </div>
                        </div>
                    )}

                    <div class="col-12">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="email"
                            onChange="" value={details.email} />
                        <div class="invalid-feedback">
                            Zadejte prosím validní email
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="telNmb" class="form-label">Telefonní číslo</label>
                        <input type="tel" class="form-control" id="telNmb"
                            onChange={e => setDetails({ ...details, telNmb: e.target.value })} value={details.telNmb} />
                        <div class="invalid-feedback">
                            Zadejte prosím validní telefononní číslo
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="organisation" class="form-label">Organizace</label>
                        <input type="text" class="form-control" id="organisation"
                            onChange={e => setDetails({ ...details, organisation: e.target.value })} value={details.organisation} />
                        <div class="invalid-feedback">
                            Zadejte existující organizaci
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="field" class="form-label">Obor</label>
                        <input type="text" class="form-control" id="field"
                            onChange={e => setDetails({ ...details, field: e.target.value })} value={details.field} />
                        <div class="invalid-feedback">
                            Zadejte platnou organizaci
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="zeme" class="form-label">Země</label>
                        <input type="text" class="form-control" id="zeme"
                            onChange={e => setDetails({ ...details, country: e.target.value })} value={details.country} />
                        <div class="invalid-feedback">
                            Zadejte existujíci zemi
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="birthday" class="form-label">Datum narození</label>
                        <input type="date" class="form-control" id="birthday"
                            onChange={e => setDetails({ ...details, birthday: e.target.value })} value={details.birthday} />
                        <div class="invalid-feedback">
                            Zadejte validní datum narození
                        </div>
                    </div>
                </div>

                <br />

                <button class="w-100 btn btn-lg btn-primary" type="submit">Potvrdit nové údaje</button>
            </div>
        </form>
    )
}

export default ProfileForm