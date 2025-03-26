/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file RezervaceFind.jsx
 */
import React, {useState} from 'react'
import RezervaceList from './RezervaceList';
import { Get } from '../../static/Loaders';

/**
 * Gets reservation by id
 * @param {*} id reservation id
 * @returns data of given reservation, null if not found
 */
async function GetRezervace(id){

    let {dataToReturn, pending, error} = await Get('http://ituprojekt.fun:8000/konference/rezervace/'+id, null);

    return dataToReturn;

}

/**
 * Searchbar for searching reservation by id
 * + table with reservations of current user
 * @returns Html
 */
export default function RezervaceFind() {

    const [id, setId] = useState(null)

    const [data, setData] = useState(null)

    async function HandleSubmit (e){
        e.preventDefault()

        let dataToReturn = await GetRezervace(id);

        setData(dataToReturn);

    }

    return (
        <div className="KonferenceRezervaceFind">
            <div class="content container-fluid">
                <div class="row mb-3 " style={{marginTop: 20}}>
                    <div class="col-12 themed-grid-col">
                        

                    <div class="input-group">
                    <div class="form-outline">
                        <label class="form-label" for="form1">Zadej ID rezervace</label>
                        <input type="search" id="form1" class="form-control" onChange={(e) => setId(e.target.value)} />
                    </div>
                    <button type="button" class="btn btn-outline-primary" onClick={(e) => HandleSubmit(e)} >Najdi rezervaci
                    </button>
                    </div>

                    {
                        data &&
                        <div>
                        id transakce: {data.ID} <br/>
                        Konference: {data.Konference} <br />

                        {
                            data.Uzivatel ?
                            <div>Uzivatel: {data.Uzivatel}</div> :
                            <div>Jmeno a Prijmeni: {data.Jmeno} {data.Prijmeni}<br />
                            Email: {data.Email}</div>
                        }
                        <br />
                        Datum vytvoreni: {data.Datum_vytvoreni} <br />
                        Pocet vstupenek: {data.Pocet_vstupeniek} <br />
                        Celkova cena: {data.Celkova_cena} <br />
                        Stav: {data.Stav}


                    </div>
                    }
                    

                    </div>
                </div>
            </div>


            <h3 class="card-title text-bold"> Moje rezervace </h3>

            <RezervaceList poradatel={false} nofilter={true}></RezervaceList>

        </div>
        
    );
}
