/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file KonferenceNew.jsx
 */
import React, {useState} from 'react'
import {useNavigate} from 'react-router-dom';
import {Post} from '../../static/Loaders';
import KonferenceForm from '../KonferenceForm';

/**
 * Container for KonferenceForm
 * @returns Html
 */
export default function KonferenceNew() {

    const navigate = useNavigate();
    const [msg, setMsg] = useState(null);

    

    const NewKonf = async details => {

        let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/vytvorit', null, JSON.stringify(details));
    
        if(error) {
            //reload get user info again
            if(dataToReturn)
                setMsg(dataToReturn.message);
            else
                setMsg(error);
        }
        else{
            setMsg(null);
            navigate('/konference/'+details.Nazev);
        }
    }

    return (
        <div className="KonferenceNew">
            <div class="content container-fluid">
                <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                    <div class="col-4 themed-grid-col">
                        
                        <KonferenceForm Update={NewKonf} setErr={setMsg}/>

                        { msg && 
                        <div>
                            <h2 style={{color: 'red'}}>Error: {msg}</h2>
                        </div>
                        }

                    </div>
                </div>
            </div>
        </div>      
        
    );
}
