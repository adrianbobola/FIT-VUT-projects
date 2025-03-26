/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file PrispevekNew.jsx
 */
import React, {useState} from 'react';
import {Post} from '../../static/Loaders';
import { useParams, useNavigate } from 'react-router';
import PrispevekForm from '../PrispevekForm';

/**
 * Container for PrispevekForm
 * @returns Html
 */
export default function KonferenceNew() {

    const navigate = useNavigate();

    let {id} = useParams()

    const [msg, setMsg] = useState(null);
    const userID = window.localStorage.getItem("userID");

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
            window.alert("Příspěvek úspěšně přidán");
            window.location.reload(1);
        }
    }

    return (
        <div className="KonferenceNew">
            <div class="content container-fluid">
                <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                    
                    <div class="col-4 themed-grid-col">
                        
                        <PrispevekForm Update={NewKonf} setErr={setMsg}/>

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
