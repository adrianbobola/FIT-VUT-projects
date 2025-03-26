/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file KonferenceList.jsx
 */
import React, { useState } from "react";
import KonferenceCard from "../cards/KonferenceCard.jsx";
import KonferenceCardNotRegistered from "../cards/KonferenceCardNotRegistered.jsx";
import {useGet} from '../../static/Loaders';
import Authentificate from "../Authentificate.jsx";

/**
 * 
 * @param {*} datas data to display
 * @param {*} isAuth is logged in
 * @returns 
 */
function InnerHtml({datas, isAuth}){

    const [filter1, setFilter1] = useState(null)
    const [filter2, setFilter2] = useState(null)
    const [filter3, setFilter3] = useState(null)
    const [filter4, setFilter4] = useState(null)    

    const data = (datas.filter(konf =>
        (filter1 ? konf.Nazev.toLowerCase().includes(filter1.toLowerCase()) : true) &&
        (filter2 ? konf.Obor.toLowerCase().includes(filter2.toLowerCase()) : true) &&
        (filter3 ? konf.Zeme.toLowerCase().includes(filter3.toLowerCase()) : true) &&
        (filter4 ? konf.Mesto.toLowerCase().includes(filter4.toLowerCase()) : true)
    ))
    

    return(
        <div class="col-12">

            <div class="content container-fluid">
                <div class="row mb-3 " style={{marginTop: 20}}>
                    <div class="col-12 themed-grid-col">
            
            <div class="input-group">

            <div class="form-outline" style={{marginRight: 20}}>
                <h2>Filtr: </h2>
            </div>

            <div class="form-outline">
                <label class="form-label" for="form1">Zadej název konference</label>
                <input type="search" id="form1" class="form-control" 
                onChange={(e) => setFilter1(e.target.value)}/>
            </div>

            <div class="form-outline">
                <label class="form-label" for="form1">Zadej obor</label>
                <input type="search" id="form1" class="form-control" 
                onChange={(e) => setFilter2(e.target.value)}/>
            </div>

            <div class="form-outline">
                <label class="form-label" for="form1">Zadej zemi</label>
                <input type="search" id="form1" class="form-control" 
                onChange={(e) => setFilter3(e.target.value)}/>
            </div>

            <div class="form-outline">
                <label class="form-label" for="form1">Zadej město</label>
                <input type="search" id="form1" class="form-control" 
                onChange={(e) => setFilter4(e.target.value)}/>
            </div>
                    </div>
                </div>
            </div>
            </div>

            { 
                data && isAuth && data.map((konference)=>(
                    <div className="konference-card" key={konference.Nazev}>
                        <KonferenceCard data={konference}/>
                    </div>
            ))}

            { 
                data && !isAuth && data.map((konference)=>(
                    <div className="konference-card" key={konference.Nazev}>
                        <KonferenceCardNotRegistered data={konference}/>
                    </div>
            ))}

                {
                !data  &&
                <div className="">
                    <h2>Zadanému filtru žádná konference</h2>
                </div>
                }

        </div>
    )
}

/**
 * Container for list of conference cards
 * @param {*} url url to use to obtain data
 * @returns 
 */
function KonferenceList({url}) {

    let {data, pending, error} = useGet(url, null)
    
    const isAuth = Authentificate.isAuth();

    if(data && data.length == 0){
        data = null;
    }

    return (
    <div className="konference">
        <div class="container-fluid content">
            <div class="row mb-3 justify-content-center">

                { error && <div>{ error }</div> }
                { pending && 
                <div>Loading...
                    <div class="spinner-border text-secondary" role="status">
                    </div>
                </div> }

                {data &&
                <InnerHtml datas={data} isAuth={isAuth} error={error} pending={pending}/> 
                }

                {
                !data  && !pending &&
                <div className="">
                    <h2>Žádné konference v systému, přidejte nějaké</h2>
                </div>
                }

            </div>
        </div>
    </div>
  );
}

export default KonferenceList;