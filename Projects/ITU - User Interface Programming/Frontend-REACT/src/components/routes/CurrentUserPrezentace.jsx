/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file CurrentUserPrezentace.jsx
 */
import React, {useState} from "react";
import { useParams } from 'react-router';
import { useGet } from '../../static/Loaders'
import PrezentaceShowTable from "../cards/PrezentaceTableReadOnly";

function CurrentUserPrezentace() {

    const { id } = useParams();

    let {data, pending, error} = useGet('http://ituprojekt.fun:8000/konference/'+id+'/prispevky', token)

return (
    <div className="Konference">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                <div class="col-12 themed-grid-col">

                {
                    data && 
                    <div>
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Prispevky v konferenci: </h3>

                                <PrezentaceShowTable Konference={id}/>

                            </div>
                        </div>
                    </div>
                }

                </div>
            </div>
        </div>
    </div>
    
  );
}

export default CurrentUserPrezentace;
