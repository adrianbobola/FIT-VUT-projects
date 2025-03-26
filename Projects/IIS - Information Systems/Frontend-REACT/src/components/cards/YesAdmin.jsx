/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file YesAdmin.jsx
 */
import React, { useState } from 'react';
import ProfileForm from "../ProfileForm";
import { Post, Put } from "../../static/Loaders";

/**
 * Container for user manipulation - admin
 * @param {*} allUsers 
 * @returns 
 */
function YesAdmin({ allUsers, showEmail }) {

  const [open, setOpen] = useState(false);
  const [updated, setUpdated] = useState(false);
  const [details, setDetails] = useState({ Heslo: "" });
  const [passwordChange, setPasswordChange] = useState(false);

  let uzivatelia = allUsers;

  let displayErr;

  const submitHandler = e => {
    e.preventDefault();

    if (details.Heslo) {
      UpdatePasword(details.Heslo);
    }
  }

  const Update = async (details, role) => {
    console.log({ details, role });

    let dataToPut = JSON.stringify({
      Jmeno: details.name, Prijmeni: details.surname,
      Heslo: details.password, Role: role || 'uzivatel', Organizace: details.organisation,
      Obor: details.field, Zeme: details.country, Datum_narozeni: details.birthday,
      Email: details.email, TelCislo: details.telNMB, Titul: details.degree
    });

    let { dataToReturn, pending: _pending, error: _error } = await Put(`http://ituprojekt.fun:8000/admin/upravit/${details.ID}`, null, dataToPut);
    let pending = _pending;
    let error = _error;

    if (_error) {
      //reload get user info again
      console.log(error);
      window.location.reload(false);
    }
    else {
      setUpdated(true)
      setTimeout(() => {
        setUpdated(false);
      }, 500);
    }
  }

  const UpdatePasword = async heslo => {

    let { dataToReturn, pending: _pending, error: _error } = await Put(`http://ituprojekt.fun:8000/admin/upravit/heslo/${uzivatelia.ID}`, null, JSON.stringify({ Heslo: heslo }));

    if (_error) {
      displayErr = _error;
    }
    else {
      setPasswordChange(false)
      setUpdated(true)
      setTimeout(() => {
        setUpdated(false);
      }, 500);
    }
  }

  let card;

  if (open) {
    card = !passwordChange ? (
      <div className="cardBody">
        <div class="bg-light px-3">
          {updated &&
            <div>
              <h2>Updated</h2>
              <div class="spinner-border text-secondary" role="status">
              </div>
            </div>
          }
          <div className="row mb-3 justify-content-center" style={{ marginTop: 20 }}>
            <div className="col-sm-4 themed-grid-col">
              <ProfileForm Update={Update} userInfo={uzivatelia} adminUpdate />
            </div>
            <div className="col-sm-4 themed-grid-col">
              <div>
                <button className="w-100 btn btn-lg btn-outline-primary"
                  onClick={() => setPasswordChange(true)}>Změnit heslo
                </button>
              </div>
              <br />
            </div>
          </div>
        </div>

      </div>
    )
      : (
        <form onSubmit={submitHandler}>
          <div className="form-inner">
            <div className="form-group">
              <button className="w-100 btn btn-lg btn-primary"
                onClick={() => setPasswordChange(false)}>Zpět
              </button>
              <br />
              <div className="form-floating">
                <label htmlFor="NoveHeslo">Nové heslo</label>
                <input type="password" className="form-control" id="NoveHeslo" placeholder="***********"
                  onChange={e => setDetails({ Heslo: e.target.value })} value={details.NoveHeslo} />
              </div>
            </div>

            <button className="w-100 btn btn-lg btn-primary" type="submit">Potvrdit heslo</button>

          </div>
        </form>
      )
  } else {
    card = null;
  }

  return (
    <div class="card">
      <div class="card-header card-header-flex">
        {showEmail ?
          <h3 class="card-title text-bold"> {uzivatelia.ID}: {uzivatelia.Email} - {uzivatelia.Prijmeni} {uzivatelia.Jmeno} </h3>
          :
          <h3 class="card-title text-bold"> {uzivatelia.ID}: {uzivatelia.Prijmeni} {uzivatelia.Jmeno} - {uzivatelia.Email} </h3>
        }
        <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
          onClick={() => setOpen(!open)}>
          <i class="nc-icon nc-stre-up"></i>
          {open ? "Skrýt" : "Zobrazit"}
        </button>
      </div>

      {card}

    </div>
  )

}

export default YesAdmin;