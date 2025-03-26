/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file Rezervace.jsx
 */
import React, {useState} from 'react';
import {Post} from '../../static/Loaders';
import { useParams } from 'react-router';
import RezervaceFormNotRegistered from '../RezervaceFormNotRegistered';
import RezervaceFormRegistered from '../RezervaceFormRegistered';
import { useGet } from '../../static/Loaders';
import Authentificate from '../Authentificate';

/**
 * Container for forms - RezervaceFormRegistered and RezervaceFormNotRegistered
 * @returns 
 */
export default function Rezervace() {

    let {id} = useParams()

    let {data, pending, error} = useGet('http://ituprojekt.fun:8000/konference/' + id, null);

    const [msg, setMsg] = useState(null);

    const userID = window.localStorage.getItem("userID");
    const isAuth = Authentificate.isAuth();

    const NewKonf = async details => {

        details.Konference = id;
        details.Uzivatel = userID;

        let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+id+'/novyPrispevek', null, JSON.stringify(details));
    
        if(error) {
            //reload get user info again
            setMsg(error);
        }
        else{
            setMsg(null);
        }
    }

    return (

        data &&
        <div className="KonferenceRezervace">
            <div class="content container-fluid">
                <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>

                    <div class="col-4 themed-grid-col">
                        

                        {
                            !isAuth ?
                            <RezervaceFormNotRegistered konfData={data}/> :
                            <RezervaceFormRegistered konfData={data}/>

                        }

                        { msg && 
                        <div>
                            <h2>Error: {msg}</h2>
                        </div>
                        }

                    </div>
                </div>
            </div>
        </div>      
        
    );
}
