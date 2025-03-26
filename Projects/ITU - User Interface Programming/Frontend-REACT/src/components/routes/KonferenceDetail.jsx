/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file KonferenceDetail.jsx
 */
import React, {useState} from "react";
import KonferenceDetailsEditable from "../cards/KonferenceDetailsEditable";
import KonferenceDetailsReadOnly from "../cards/KonferenceDetailsReadOnly";

import MistnostiTable from "../cards/MistnostiTable";
import MistnostiTableReadOnly from "../cards/MistnostiTableReadOnly";

import PrezentaceTable from "../cards/PrezentaceTable";
import PrezentaceTableAdmin from "../cards/PrezentaceTableAdmin";
import PrezentaceTableReadOnly from "../cards/PrezentaceTableReadOnly";
import PrezentaceTableUserEdit from "../cards/PrezentaceTableUserEdit";

import RezervaceTable from "../cards/RezervaceTable";
import { useParams } from 'react-router';
import { useGet } from '../../static/Loaders'

/**
 * KonferenceDetail for logged in users
 * @returns Html
 */
function KonferenceDetail() {

    const { id } = useParams();

    //+id
    let {data, pending, error} = useGet('http://ituprojekt.fun:8000/konference/' + id, null)

    let jePoradatel = data ? window.localStorage.getItem("userID") == data.Poradatel : null

    const submitHandler = e => {
        e.preventDefault();
    }

return (
    <div className="Konference">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>

                <div class="col-12 themed-grid-col">
                    
                {
                    data && 
                    (
                    <div>
                        {  //detaily Konference
                        jePoradatel ?
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Detaily konference: {data.Nazev} </h3>

                                <KonferenceDetailsEditable data={data}></KonferenceDetailsEditable>

                            </div>
                        </div> :
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Detaily konference: {data.Nazev} </h3>

                                <KonferenceDetailsReadOnly data={data}></KonferenceDetailsReadOnly>

                            </div>
                        </div>
                        }

                        {  //Mistnosti
                        jePoradatel ?
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Místnosti </h3>

                                <MistnostiTable Konference={data.Nazev}></MistnostiTable>

                            </div>
                        </div> :
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Místnosti </h3>

                                <MistnostiTableReadOnly Konference={data.Nazev}></MistnostiTableReadOnly>

                            </div>
                        </div>
                        }

                        {  //Prezentace
                            jePoradatel ?
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Všetky príspevky </h3>
                                    <PrezentaceTableAdmin Konference={data.Nazev}
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/prispevky'}
                                    ></PrezentaceTableAdmin>
                                </div>
                            </div>
                            :
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Všetky schválené príspevky </h3>
                                    <PrezentaceTableReadOnly Konference={data.Nazev} 
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/prispevky/schvalene'}>
                                    </PrezentaceTableReadOnly>
                                </div>
                            </div>
                        }

                        {  //Prezentace neschvalene
                            jePoradatel ?
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Příspevky ke schválení </h3>
                                    <PrezentaceTableAdmin Konference={data.Nazev}
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/prispevky/neschvalene'}
                                    ></PrezentaceTableAdmin>
                                </div>
                            </div>
                            :
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Mé prispevky ke schválení </h3>
                                    <PrezentaceTableUserEdit Konference={data.Nazev}
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/prispevky/neschvalene'}
                                    ></PrezentaceTableUserEdit>
                                </div>
                            </div>
                        }

                        {  //Prezentace mePrispevky
                            jePoradatel ?
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Mé prispevky v konferenci </h3>
                                    <PrezentaceTable Konference={data.Nazev} userID={window.localStorage.getItem("userID")}
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/prispevky/neschvalene'}
                                    ></PrezentaceTable>
                                </div>
                            </div>
                            :
                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> Všechny mé prispevky v konferenci </h3>
                                    <PrezentaceTableReadOnly Konference={data.Nazev} userID={window.localStorage.getItem("userID")}
                                    url={'http://ituprojekt.fun:8000/konference/'+id+'/prispevky/neschvalene'}
                                    ></PrezentaceTableReadOnly>
                                </div>
                            </div>
                        }


                            <div class="card">
                                <div class="card-header card-header-flex">
                                    <h3 class="card-title text-bold"> { jePoradatel ? "Rezervace vstupenek na konferenci" : "Moje rezervace vstupenek na konferenci"} </h3>
                                    <RezervaceTable Konference={data.Nazev} poradatel={jePoradatel}>
                                    </RezervaceTable>
                                </div>
                            </div>

                    </div>
                    )
                }

                </div>
            </div>
        </div>
    </div>
    
  );
}

export default KonferenceDetail;
