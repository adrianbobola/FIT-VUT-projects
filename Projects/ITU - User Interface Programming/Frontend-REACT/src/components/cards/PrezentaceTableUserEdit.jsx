/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file PrezentaceTableUserEdit.jsx
 */
import React, { useState, Fragment } from "react";
import "./MistnostiTable.css";
import ReadDeleteRow from "./components/PrezentaceReadDeleteRow";
import EditableRow from "./components/PrezentaceEditableRowUser";
import { useGet, Post, Put } from "../../static/Loaders";
import { useParams } from "react-router";

async function Add(details){
  console.log("details");

  let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+details.Konference+'/novyPrispevek', null, JSON.stringify(details));
  
  return error
}


const Update = async details => {
  console.log("updating room");

  let {dataToReturn, pending, error} = await Put('http://ituprojekt.fun:8000/konference/'+details.Konference+'/prispevky/'+details.ID+'/upravit', null, JSON.stringify(details));
  
  return error
}

const Delete = async details => {
  console.log("deleting room");

  let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+details.Konference+'/prispevky/'+details.ID+'/odstranit', null, null);

  return error
}

/**
 * Table with presentations
 * @param {*} Konference conference name
 * @param {*} Mistnost room code
 * @param {*} data data
 * @returns Html
 */
function GenerateHtml({Konference, Mistnost, data}){
  const [opened, setOpened] = useState(false);
  const [prezentace, setPrezentace] = useState(data);

  const [addFormData, setAddFormData] = useState({
    ID: null,
    Nazev: "",
    Konference: "",
    Uzivatel: "",
    Popis: "",
    Tagy: "",
    Grafika: "",
    Soubor: "",
    Mistnost: "",
    jeSchvalena: "",
    Datum: "",
    Zacatek_cas: "",
    Konec_cas: "",
    poznamkyPoradatele: ""
  });

  const [editFormData, setEditFormData] = useState({
    ID: null,
    Nazev: "",
    Konference: "",
    Uzivatel: "",
    Popis: "",
    Tagy: "",
    Grafika: "",
    Soubor: "",
    Mistnost: "",
    jeSchvalena: "",
    Datum: "",
    Zacatek_cas: "",
    Konec_cas: "",
    poznamkyPoradatele: ""
  });

  const [editRoomNazev, setEditRoomNazev] = useState(null);

  const handleEditFormChange = (event) => {
    event.preventDefault();

    const fieldName = event.target.getAttribute("name");
    const fieldValue = event.target.value;

    const newFormData = { ...editFormData };
    newFormData[fieldName] = fieldValue;

    setEditFormData(newFormData);
  };

  const handleAddFormSubmit = async (event) => {
    event.preventDefault();

    const newPrezentace = {
      Nazev: addFormData.Nazev,
      Konference: Konference,
      Uzivatel: null,
      Popis: addFormData.Popis,
      Tagy: addFormData.Tagy,
      Grafika: addFormData.Grafika,
      Soubor: addFormData.Soubor,
      Mistnost: addFormData.Mistnost,
      jeSchvalena: addFormData.jeSchvalena,
      Datum: addFormData.Datum === "" ? null : addFormData.Datum,
      Zacatek_cas: addFormData.Zacatek_cas === "" ? null : addFormData.Zacatek_cas,
      Konec_cas: addFormData.Konec_cas === "" ? null : addFormData.Konec_cas,
      poznamkyPoradatele: addFormData.poznamkyPoradatele
    };

    let error = await Add(newPrezentace);

    if(!error){
      const newDatas = [...prezentace, newPrezentace];
      setPrezentace(newDatas);
    }
    else{
      //we can display error
    }

  };

  const handleEditFormSubmit = async (event) => {
    event.preventDefault();

    const editPrezentace = {
      ID: editFormData.ID,
      Nazev: editFormData.Nazev,
      Konference: Konference,
      Uzivatel: editFormData.Uzivatel,
      Popis: editFormData.Popis,
      Tagy: editFormData.Tagy,
      Grafika: editFormData.Grafika,
      Soubor: editFormData.Soubor,
      Mistnost: editFormData.Mistnost,
      jeSchvalena: editFormData.jeSchvalena,
      Datum: editFormData.Datum === "" ? null : editFormData.Datum,
      Zacatek_cas: editFormData.Zacatek_cas === "" ? null : editFormData.Zacatek_cas,
      Konec_cas: editFormData.Konec_cas === "" ? null : editFormData.Konec_cas,
      poznamkyPoradatele: editFormData.poznamkyPoradatele
    };


    let error = await Update(editPrezentace)

    if(!error){
      const newDatas = [...prezentace];

      const index = prezentace.findIndex((room) => room.ID === editRoomNazev);
  
      newDatas[index] = editPrezentace;
  
      setPrezentace(newDatas);
      setEditRoomNazev(null);
    }
    else{
      //we can display error
    }
  };

  const handleEditClick = (event, room) => {
    event.preventDefault();
    setEditRoomNazev(room.ID);

    const formValues = {
      ID: room.ID,
      Nazev: room.Nazev,
      Konference: room.Konference,
      Uzivatel: room.Uzivatel,
      Popis: room.Popis,
      Tagy: room.Tagy,
      Grafika: room.Grafika,
      Soubor: room.Soubor,
      Mistnost: room.Mistnost,
      jeSchvalena: room.jeSchvalena,
      Datum: room.Datum === "" ? null : room.Datum,
      Zacatek_cas: room.Zacatek_cas === "" ? null : room.Zacatek_cas,
      Konec_cas: room.Konec_cas === "" ? null : room.Konec_cas,
      poznamkyPoradatele: room.poznamkyPoradatele
    };

    setEditFormData(formValues);
  };

  const handleCancelClick = () => {
    setEditRoomNazev(null);
  };

  const handleDeleteClick = async (prezentKod) => {
    const newDatas = [...prezentace];

    const index = prezentace.findIndex((prez) => prez.Kod === prezentKod);

    let details = newDatas[index];

    let error = await Delete({ID: prezentKod});

    if(!error){
      newDatas.splice(index, 1);

      setPrezentace(newDatas);
    }

  };

  let card = (
    data &&
    <div className="app-container">
      <form onSubmit={handleEditFormSubmit}>
        <div class="table-responsive">
          <table class="table table-striped">
            <thead>
              <tr>
                <td>Nazev</td>
                <td>Konference</td>
                <td>Uzivatel</td>
                <td>Popis</td>
                <td>Tagy</td>
                <td>Grafika</td>
                <td>Soubor</td>
                <td>Mistnost</td>
                <td>Schvalena</td>
                <td>Zacatek cas</td>
                <td>Konec cas</td>
                <td>poznamkyPoradatele</td>
              </tr>
            </thead>
            <tbody>
              {prezentace.map((room) => (
                <Fragment>
                {
                editRoomNazev === room.ID ? (
                  <EditableRow
                    editFormData={editFormData}
                    handleEditFormChange={handleEditFormChange}
                    handleCancelClick={handleCancelClick}
                  />
                ) : (
                  <ReadDeleteRow
                    data={room}
                    handleEditClick={handleEditClick}
                    handleDeleteClick={handleDeleteClick}
                  />
                )}
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
 * Table with presentions created by user for conference, yet waiting for approval
 * @param {*} Konfernece conference name
 * @param {*} Mistnost name of room
 * @param {*} url url to ge data from
 * @returns 
 */
function PrezentaceUserEdit ({Konference, Mistnost, url}) {

  let {id, kod} = useParams();

  let {data, pending, error} = useGet(url, null)

  const userID = window.localStorage.getItem("userID");


  if(data){
    let filteredData = data.filter(e => e.Uzivatel == userID );

    data = filteredData;
  }

  return(data && 
    <div>
      <GenerateHtml data={data} Konference={id} Mistnost={kod}></GenerateHtml>
    </div>
    )

};

export default PrezentaceUserEdit;