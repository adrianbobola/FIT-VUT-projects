/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file CurrentUserProfile.jsx
 */
import React, { useEffect, useState } from 'react'
import Authentificate from '../Authentificate';
import ProfileForm from '../ProfileForm';
import PasswordChange from '../cards/PasswordChange';
import { useGet, Put, Post } from '../../static/Loaders';
import DeleteUser from '../cards/DeleteUser';
import { useNavigate } from 'react-router';

/**
 * Container for currently logged in user and its profile options
 * @param {*} token user token
 * @returns 
 */
function CurrentUserProfile(token) {

    const [updated, setUpdated] = useState(false);
    const [passwordChange, setPasswordChange] = useState(false);
    const navigate = useNavigate();

    let displayErr;

    let { data: userInfo, pending, error } = useGet('http://ituprojekt.fun:8000/uzivatel/', token)


    let id3 = window.localStorage.getItem("userID");
    //data, pending, error
    let { data: data3, pending: pending3, error: error3 } = useGet('http://ituprojekt.fun:8000/admin/check/' + id3, null)
    let isAdmin;
    if (error3) {
        isAdmin = false;
    }
    else if (data3){
        isAdmin = data3.admin;
    }


    const Update = async details => {
        console.log("details");

        let dataToPut = JSON.stringify({
            Jmeno: details.name, Prijmeni: details.surname,
            Heslo: details.password, Role: "uzivatel", Organizace: details.organisation,
            Obor: details.field, Zeme: details.country, Datum_narozeni: details.birthday,
            Email: details.email, TelCislo: details.telNMB, Titul: details.degree
        });

        let { dataToReturn, pending: _pending, error: _error } = await Put('http://ituprojekt.fun:8000/uzivatel/upravit', null, dataToPut);
        //userInfo = data;
        pending = _pending; //this wont show saddly :/
        error = _error;

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

    const UpdatePasword = async details => {

        let { dataToReturn, pending: _pending, error: _error } = await Put('http://ituprojekt.fun:8000/uzivatel/upravit/heslo', null, JSON.stringify(details));

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

    const deleteUser = async (e) => {

        let { dataToReturn, pending: _pending, error: _error } = await Post('http://ituprojekt.fun:8000/uzivatel/odstranit', null, null);

        if (_error) {
            displayErr = _error;
        }
        else {
            Authentificate.logout();
        }
    }

    const redirectToUpload = () => {
        window.location.href = 'http://www.ituprojekt.fun/upload/';
    }

    return (
        <div className="currentUserProfile">
            <div class="content container-fluid">
                <div class="row mb-3 justify-content-center" style={{ marginTop: 20 }}>
                    <div class="col-sm-4 themed-grid-col">

                        {error && <div>{error}</div>}
                        {pending &&
                            <div>Loading...
                                <div class="spinner-border text-secondary" role="status">
                                </div>
                            </div>}
                        {updated &&
                            <div>
                                <h2>Updated</h2>
                                <div class="spinner-border text-secondary" role="status">
                                </div>
                            </div>
                        }

                        {userInfo && !passwordChange &&
                            <div>
                                <ProfileForm Update={Update} userInfo={userInfo} />
                                <br />

                            </div>
                        }
                        {passwordChange &&
                            <div>
                                <h2>{error}</h2>
                                <div class="spinner-border text-secondary" role="status">
                                </div>
                            </div>
                            &&
                            <div>
                                <PasswordChange Update={UpdatePasword} goBack={setPasswordChange}></PasswordChange>

                            </div>


                        }

                    </div>

                    {userInfo && !passwordChange &&
                        <div class="col-sm-4 themed-grid-col">
                            <div>
                                <button class="w-100 btn btn-lg btn-outline-primary"
                                    onClick={() => navigate('konference')}>Zobraz mé koference</button>
                            </div>
                            <br />
                            <div>
                                <button class="w-100 btn btn-lg btn-outline-primary"
                                    onClick={() => navigate('prezentace')}>Zobraz mé příspěvky</button>
                            </div>
                            <br />
                            <div>
                                <button class="w-100 btn btn-lg btn-outline-primary"
                                    onClick={redirectToUpload}>Upload server</button>
                            </div>
                            <br />
                            {
                                isAdmin?
                                    <div>
                                            <button class="w-100 btn btn-lg btn-outline-primary"
                                            onClick={() => navigate('/admin')}>Admin</button>
                                        <br />
                                    </div>
                                    :
                                    <div>
                                    </div>
                            }
                            <br />
                            <div>
                                <button class="w-100 btn btn-lg btn-outline-primary"
                                    onClick={() => setPasswordChange(true)}>Změnit heslo</button>
                            </div>
                            <br />
                            <DeleteUser Delete={deleteUser}></DeleteUser>
                        </div>
                    }

                </div>
            </div>
        </div>
    )
}

export default CurrentUserProfile;