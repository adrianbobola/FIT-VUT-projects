/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file LoginForm.jsx
 */
import React, { useState } from 'react'

/**
 * Login form
 * @param Login login fnc
 * @param error error
 * @returns Html
 */
function LoginForm({Login, error}) {

    const [details, setDetails] = useState({Email: "", Heslo: ""});

    const submitHandler = e => {
        e.preventDefault();

        Login(details);
    }

    return (
        <form onSubmit={submitHandler}>
            <div className="form-inner">
                <h1 class="h3 mb-3 fw-normal">Přihlášení</h1>
		<p>Přihlaste se k svému účtu, čím získáte možnost zakládat konference, stát se přednášejícím na konferenci, spravovat svoje vstupenky a mnoho dalšího</p>
                <div className="form-group">
                    <div class="form-floating">
                        <label htmlFor="floatingInput">Email</label>
                        <input type="email" class="form-control" id="Email" placeholder="neco@example.com"
                        onChange={e => setDetails({...details, Email: e.target.value})} value={details.Email}/>
                    </div>
                    <div class="form-floating">
                        <label htmlFor="Heslo">Heslo</label>
                        <input type="password" class="form-control" id="Heslo" placeholder="Zadejte heslo"
                        onChange={e => setDetails({...details, Heslo: e.target.value})} value={details.Heslo}/>
                    </div>
                </div>

                <button class="w-100 btn btn-lg btn-primary" type="submit">Přihlásit se</button>
		<p> </p>
		<p>Nemáte ještě u nás účet? Zaregistrovat si ho můžete hned teď!</p>

            </div>
        </form>
    )
}

export default LoginForm
