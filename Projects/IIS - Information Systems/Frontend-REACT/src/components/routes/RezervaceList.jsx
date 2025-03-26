/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file RezervaceList.jsx
 */
import React from "react";
import RezervaceTable from "../cards/RezervaceTable";
import { useParams } from 'react-router';

/**
 * Container for RezervaceTable
 * @param {*} poradatel user for which genera
 * @param {*} nofilter whether to use filter, boolean
 * @returns Html
 */
function RezervaceList({poradatel, nofilter}) {

    const { id } = useParams();

    const submitHandler = e => {
        e.preventDefault();
    }

return (
    <div className="Rezervace">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>

                <div class="col-12 themed-grid-col">
                    
                <RezervaceTable Konference={id} poradatel={poradatel} nofilter={nofilter} ></RezervaceTable>

                </div>
            </div>
        </div>
    </div>
    
  );
}

export default RezervaceList;
