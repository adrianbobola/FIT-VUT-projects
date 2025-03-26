/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file RezervaceTable.jsx
 */
import React, { useState, Fragment } from "react";
import "./MistnostiTable.css";
import RezervacePotvrditRow from "./components/RezervacePotvrditRow";
import {useGet, Put, Post} from '../../static/Loaders'


const Update = async details => {
    console.log("updating room");

    let {dataToReturn, pending, error} = await Put('http://ituprojekt.fun:8000/konference/'+details.Konference+'/rezervace/'+details.ID+'/potvrdit', null, JSON.stringify(details));

    return error
  }
  
const Delete = async details => {
    console.log("deleting room");

    let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+details.Konference+'/rezervace/'+details.ID+'/odstranit', null, null);

    return error
  }

/**
 * Table with presentations
 * @param {*} Konference conference name
 * @param {*} data data
 * @param {*} poradatel boolean wheter we are creator of conference
 * @returns Html
 */
function GenerateHtml({Konference, data, poradatel}){

    const [opened, setOpened] = useState(false);
    const [prezentace, setPrezentace] = useState(data);

    const handlePotvrditClick = async (event, prezentKod) => {
        event.preventDefault();
        const newDatas = [...prezentace];
    
        const index = prezentace.findIndex((prez) => prez.ID === prezentKod);
    
        let details = newDatas[index];

        details.Stav = "zaplaceno"
    
        let error = await Update(details);
    
        if(!error){
          newDatas[index] = details;

          setPrezentace(newDatas);
        }
    }

    const handleDeleteClick = async (prezentKod) => {
        const newDatas = [...prezentace];
    
        const index = prezentace.findIndex((prez) => prez.ID === prezentKod);
    
        let details = newDatas[index];
    
        let error = await Delete(details);
    
        if(!error){
          newDatas.splice(index, 1);
    
          setPrezentace(newDatas);
        }
    }

    let card = (
        data &&
        <div className="app-container">
          <form onSubmit="">
            <div>
    
            <table>
              <thead>
                <tr>
                  {poradatel && <th>Konference</th>}
                  <th>Email</th>
                  <th>Datum vytvoreni</th>
                  <th>Pocet vstupenek</th>
                  <th>Celkova cena</th>
                  <th>Stav</th>
                </tr>
              </thead>
              <tbody>
                {prezentace.map((room) => (
                  <Fragment>
                    <RezervacePotvrditRow data={room} handleEditClick={handlePotvrditClick} 
                    handleDeleteClick={handleDeleteClick} poradatel={poradatel}/>
                </Fragment>
                ))}
              </tbody>
            </table>
    
            </div>
          </form>
        </div>
      );

      return(
        <div>
            <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
                    onClick={(() => setOpened(!opened))}>
                <i class="nc-icon nc-stre-up"></i>
                {opened ? "Skrýt" : "Zobrazit"}
            </button>
            {opened && card}
        </div>
      );
}

/**
 * reservation table, for attendee of conference or creator of conference
 * @param {*} Konference id of konference
 * @param {*} nofilter whether to use filter
 * @param {*} poradatel whether user is poradatel - creator of conference
 * @returns 
 */
function RezervaceTable ({Konference, nofilter = false, poradatel}) {

    let dataToUse
    let url = poradatel ? 
        'http://ituprojekt.fun:8000/konference/' + Konference+ '/rezervace' :
        'http://ituprojekt.fun:8000/uzivatel/rezervace';

    let {data, pending, error} = useGet(url, null);

    dataToUse = data;

    if(data && !poradatel && !nofilter){
        data = dataToUse.filter(e => e.Konference == Konference );

        dataToUse = data;
    }

    return(data && 
        <div>
            <GenerateHtml data={dataToUse} Konference={Konference} poradatel={poradatel}></GenerateHtml>
        </div>
        
        )
};

export default RezervaceTable;