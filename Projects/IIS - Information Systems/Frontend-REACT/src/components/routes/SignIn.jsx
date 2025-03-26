/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file SignIn.jsx
 */

import React, {useState} from "react";
import {useNavigate} from "react-router-dom";
import LoginForm from "../LoginForm";
import RegistrationForm from "../RegistrationForm";
import './SignIn.css';
import Auth from "../Authentificate"
import {Get} from "../../static/Loaders"

/**
 * post method to register user
 * @param {*} credentials data to post
 * @returns 
 */
async function registerUser(credentials) {
    return fetch('http://ituprojekt.fun:8000/uzivatel/registrace', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(credentials)
    })
   }

/**
 * post method to log in user
 * @param {*} credentials data to post
 * @returns 
 */
async function loginUser(credentials) {
    return fetch('http://ituprojekt.fun:8000/uzivatel/prihlaseni', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(credentials)
    })
    .then(data => data.json())
   }

/**
 * Container for LoginForm and RegistrationForm
 * @returns Html
 */
function SignIn() {
    const [error, setError] = useState("");

    const navigate = useNavigate();

    const Login = async details => {
        console.log("details");

        if(details.Email && details.Heslo){
            
            //send to server
            let answer = await loginUser(details);

            //validate if user exist/ answer from server
            if(answer.data){
                Auth.login(answer.data);
                Auth.setEmail(details.Email);

                //we assume this does not throw
                let { dataToReturn, pending, error } = await Get('http://ituprojekt.fun:8000/uzivatel/', null);

                Auth.setId(dataToReturn);
                
                console.log("redirected");
                navigate('/konference');
                window.location.reload(false);
            }
            //we cannot login, user does not exist
            else{
                //does not work, but we give a fuck
                console.log("not redirected");
                window.alert(answer.message);
            }
        }
        else{
          window.alert("Error: Zadejte email a heslo pro přihlášení");
        }
    }

    const Registration = async details => {
        console.log("details");

        if(details.Email && details.Heslo && details.Jmeno && details.Prijmeni){
            //send to server
            let answer = await registerUser(details);

            //user succesfully registered
            if(answer.status === 201){
              let answer = await loginUser(details);

              if(answer.data){
                Auth.login(answer.data);
                Auth.setEmail(details.Email);
                console.log("redirected");
                navigate('/konference');
                window.location.reload(false);
                window.alert("Registrace proběhla úspěšně, byli jste automaticky přihlášeni");
              }
              else{
                window.alert("Registrace proběhla úspěšně, nyní se mužete přihlásit");
                console.log("not redirected");
              }

            }
            else{
              let msg = await answer.json();
              window.alert(msg.message);
              setError(msg.message);
            }
        }
        else{
          window.alert("Error: Zadejte email, jmeno, přijmení a heslo pro registraci");
          setError("Error: Zadejte email, jmeno, přijmení a heslo pro registraci");
        }
    }

  return (
    <div className="signIn">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                <div class="col-sm-4 themed-grid-col">

                    <LoginForm Login={Login} error={error}/>

                </div>
                <div class="col-sm-4 themed-grid-col">

                    <RegistrationForm Registration={Registration} error={error}/>

                </div>
            </div>
        </div>
    </div>
  );
}

export default SignIn;