/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file UserProfile.jsx
 */
import React, {useState} from 'react'
import { useParams } from 'react-router-dom';
import {useGet} from "../../static/Loaders"

/**
 * 
 * @param {*} data data to display
 * @returns Html
 */
function InnerHtml({data}){
    const details = data;

    return (
        <form onSubmit="" class="needs-validation" novalidate="">
            <div className="form-inner">
            <h1 class="h3 mb-3 fw-normal">Údaje</h1>

                <div class="row g-3">
                    <div class="col-sm-6">
                        <label for="name" class="form-label">Jméno</label>
                        <input type="text" class="form-control" id="name"
                        onChange="" value={details.Jmeno}/>
                    </div>

                    <div class="col-sm-6">
                        <label for="surname" class="form-label">Příjmení</label>
                        <input type="text" class="form-control" id="surname"
                        onChange="" value={details.Prijmeni}/>
                    </div>

                    <div class="col-sm-6">
                        <label for="degree" class="form-label">Titul</label>
                        <br />
                        <select class="form-select" id="degree" 
                        onChange="" value={details.Titul ? details.Titul : "" }>
                        </select>
                    </div>


                    <div class="col-12">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="email"
                        onChange="" value={details.Email ? details.Email : "" }/>
                    </div>

                    <div class="col-12">
                        <label for="telNmb" class="form-label">Telefonní číslo</label>
                        <input type="tel" class="form-control" id="telNmb"
                        onChange="" value={details.TelCislo ? details.TelCislo : "" }/>
                        <div class="invalid-feedback">
                            Zadejte prosím validní telefononní číslo
                        </div>
                    </div>

                    <div class="col-12">
                        <label for="organisation" class="form-label">Organizace</label>
                        <input type="text" class="form-control" id="organisation"
                        onChange="" value={details.Organizace ? details.Organizace : "" }/>
                    </div>

                    <div class="col-12">
                        <label for="field" class="form-label">Obor</label>
                        <input type="text" class="form-control" id="field"
                        onChange="" value={details.Obor ? details.Obor : "" }/>
                    </div>

                    <div class="col-12">
                        <label for="zeme" class="form-label">Země</label>
                        <input type="text" class="form-control" id="zeme"
                        onChange="" value={details.Zeme ? details.Zeme : "" }/>
                    </div>

                    <div class="col-12">
                        <label for="birthday" class="form-label">Datum narození</label>
                        <input type="date" class="form-control" id="birthday"
                        onChange="" value={details.Datum_narozeni ? details.Datum_narozeni : "" }/>
                    </div>
                </div>

                {/* This is just horizontal break.. */}
                {/* <hr class="my-4"/> */}
                <br/>

            </div>
        </form>
    )
}

/**
 * profile of user
 * @returns Html
 */
function UserProfile() {

    let {id} =  useParams()

    let {data, pending, error} = useGet('http://ituprojekt.fun:8000/uzivatel/'+id, null);

    return(
        data && 

        <div>
            <div class="card">
                <div class="card-header card-header-flex">
                    <h3 class="card-title text-bold"> Informace o uživateli </h3>

                    <InnerHtml data={data}></InnerHtml>

                </div>
            </div>
        </div>
    )

}

export default UserProfile
