/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file Admin.jsx
 */
import React, { useState } from "react";
import { useGet } from '../../static/Loaders';
import { useParams } from 'react-router';
import PersonListDelete from "../PersonListDelete";

/**
 * Container for admin page
 * @returns Html
 */
function Admin() {

    let id = window.localStorage.getItem("userID");
    let { data, pending, error } = useGet('http://ituprojekt.fun:8000/admin/check/' + id, null)



    let jeAdmin;

    if (error) {
        jeAdmin = false;
    }
    else if (data)
        jeAdmin = data.admin;


    return (
        <div className="uzivatelia">
            <div class="container-fluid content">
                <div class="row mb-3 justify-content-center">
                    <div class="col-12">
                        {(pending) &&
                            <div>Loading...
                                <div class="spinner-border text-secondary" role="status">
                                </div>
                            </div>
                        }
                        {(!pending) && jeAdmin ?
                            <div>
                                <PersonListDelete />
                            </div>
                            :
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Nejste administrátor! </h3>
                                </div>
                            </div>
                        }
                    </div>
                </div>
            </div>
        </div>
    );

}

export default Admin;
