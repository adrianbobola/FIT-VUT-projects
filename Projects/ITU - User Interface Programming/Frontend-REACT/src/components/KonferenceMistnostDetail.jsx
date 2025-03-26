/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file KonferenceMistnostDetail.jsx
 */
import React, {useState} from "react";
import PrezentaceTableReadOnly from "./cards/PrezentaceTableReadOnly";
import { useParams } from 'react-router';

/**
 * Detail with prezentations in choosen room in choosen conference, given by params
 * @returns Html
 */
function KonferenceMistnostDetail() {

    const { id, kod } = useParams();


return (
    <div className="Konference">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                <div class="col-12 themed-grid-col">

                    <div>
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Prezentace v místnosti + {kod} v konferenci {id} </h3>

                                <PrezentaceTableReadOnly Konference={id} Mistnost={kod} 
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/'+kod+'/prispevky'}
                                ></PrezentaceTableReadOnly>

                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>
    
  );
}

export default KonferenceMistnostDetail;
