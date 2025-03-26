/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file Harmonogram.jsx
 */
import React, {useState} from "react";
import { useParams } from 'react-router';
import PrezentaceShowTable from "../cards/PrezentaceTableReadOnly";

/**
 * Harmonogram of prezentation for conference determined by id
 * @returns Html
 */
function Harmonogram() {

    const { id } = useParams();

    //+id
    let url = 'http://ituprojekt.fun:8000/konference/'+id+'/prispevky/schvalene';


return (
    <div className="Konference">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                <div class="col-12 themed-grid-col">
                    
                {
                    <div>
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Prispevky v konferenci: </h3>

                                <PrezentaceShowTable Konference={id} url={url}  Harmonogram={true}/>

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

export default Harmonogram;
