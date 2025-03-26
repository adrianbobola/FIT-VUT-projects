/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file PasswordChange.jsx
 */
import React, { useState } from 'react'

/**
 * password change form
 * @param Update function to call on submit
 * @param goBack setter for going back from changing password
 * @returns 
 */
function NoveHesloChange({Update, goBack}) {

    const [details, setDetails] = useState({Heslo: "", NoveHeslo: ""});

    const submitHandler = e => {
        e.preventDefault();

        if(details.Heslo && details.NoveHeslo){
            Update(details);
        }
    }

    return (
        <form onSubmit={submitHandler}>
            <div className="form-inner">
                <div className="form-group">
                <button class="w-100 btn btn-lg btn-primary"
                onClick={() => goBack(false)}>Zpět</button>
                <br/>
                    <div class="form-floating">
                        <label htmlFor="floatingInput">Staré heslo:</label>
                        <input type="password" class="form-control" id="Heslo" placeholder="***********"
                        onChange={e => setDetails({...details, Heslo: e.target.value})} value={details.Heslo}/>
                    </div>
                    <div class="form-floating">
                        <label htmlFor="NoveHeslo">Nové heslo</label>
                        <input type="password" class="form-control" id="NoveHeslo" placeholder="***********"
                        onChange={e => setDetails({...details, NoveHeslo: e.target.value})} value={details.NoveHeslo}/>
                    </div>
                </div>

                <button class="w-100 btn btn-lg btn-primary" type="submit">Potvrdit heslo</button>

            </div>
        </form>
    )
}

export default NoveHesloChange
