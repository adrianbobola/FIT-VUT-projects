/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file PrezentaceTableReadOnly.jsx
 */
import React, { useState, Fragment } from "react";
import "./MistnostiTable.css";
import ReadRow from "./components/PrezentaceReadRow";
import {useGet} from '../../static/Loaders'

/**
 * Table with presentations
 * @param {*} data data
 * @returns Html
 */
function GenerateHtml({data}){
  const [opened, setOpened] = useState(false);

  let card = (
    <div className="app-container">
      <form onSubmit="">
        <div class="table-responsive">

        <table class="table table-striped">
          <thead>
            <tr>
              <th>Nazev</th>
              <th>Konference</th>
              <th>Prednasajuci</th>
              <th>Popis</th>
              <th>Tagy</th>
              <th>Grafika</th>
              <th>Soubor</th>
              <th>Mistnost</th>
              <th>Schavalena</th>
              <th>Zacatek cas</th>
              <th>Konec cas</th>
              <th>Poznamky poradatele</th>
            </tr>
          </thead>
          <tbody>
            {data.map((room) => (
              <Fragment>
                <ReadRow data={room}/>
            </Fragment>
            ))}
          </tbody>
        </table>

        </div>
      </form>
    </div>
  )

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
 * Table with presentions created by user for conference, yet waiting for approval
 * @param {*} Konfernece conference name
 * @param {*} Mistnost name of room
 * @param {*} url url to ge data from
 * @param {*} userID user id
 * @param {*} Harmonogram boolean, whether to filter data for creation of harmonogram
 * @returns 
 */
function PrezentaceTableReadOnly ({Konference, url, userID, Harmonogram}) {

  if(url){

  }
  else
      url = 'http://ituprojekt.fun:8000/konference/'+Konference+'/prispevky';


  let {data, pending, error} = useGet(url, null)

  if(data){
    if(userID){
      let filteredData = data.filter(e => e.Uzivatel == userID );

      data = filteredData;
    }
    if(Harmonogram){
      let filteredData = data.sort((e1, e2) => ( e2.Zacatek_cas < e1.Zacatek_cas ));

      data = filteredData;
    }
  }

  return (
    data ?
    <GenerateHtml data={data}/>
    :
    (
    <div>
      Zadne prispevky :(
    </div>
    )
    
  );
};

export default PrezentaceTableReadOnly;