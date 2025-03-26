/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file MistnostiTableReadOnly.jsx
 */
import React, { useState, Fragment } from "react";
import "./MistnostiTable.css";
import ReadOnlyRow from "./components/MistnostiReadRow";
import { useGet } from "../../static/Loaders";

/**
 * Table with rooms
 * @param {*} Konference conference name
 * @param {*} data data to use
 * @returns Html
 */
function GenerateHtml({data, Konference}){
  const [opened, setOpened] = useState(false);

  let card = (
    data &&
    <div className="app-container">
      <form onSubmit="">
        <div class="table-responsive">
          <table class="table table-striped">
            <thead>
              <tr>
                <th>Kod</th>
                <th>Popis</th>
                <th>Vybaveni</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.map((room) => (
                <Fragment>
                  <ReadOnlyRow
                    data={room}
                  />
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
  
};

/**
 * Table with rooms only for read
 * @param {*} Konference conference name
 * @returns Html
 */
function MistnostiTableReadOnly ({Konference}) {

  let {data, pending, error} = useGet('http://ituprojekt.fun:8000/konference/'+Konference+'/mistnosti', null)

  return(data && 
    <div>
      <GenerateHtml data={data} Konference={Konference}></GenerateHtml>
    </div>
    
    )
};

export default MistnostiTableReadOnly;