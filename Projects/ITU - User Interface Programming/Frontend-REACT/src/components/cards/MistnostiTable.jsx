/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file MistnostiTable.jsx
 */
import React, { useState, Fragment } from "react";
import "./MistnostiTable.css";
import ReadOnlyRow from "./components/MistnostiReadDeleteRow";
import EditableRow from "./components/MistnostiEditableRow";
import { Post, Put, useGet } from "../../static/Loaders";


async function Add(details){
  console.log("details");

  let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+details.Konference+'/novaMistnost', null, JSON.stringify(details));
  
  return error
}


async function Update(details){
  console.log("updating room");

  let {dataToReturn, pending, error} = await Put('http://ituprojekt.fun:8000/konference/'+details.Konference+'/mistnost/upravit', null, JSON.stringify(details));
  
  return error
}

const Delete = async details => {
  console.log("deleting room");

  let {dataToReturn, pending, error} = await Post('http://ituprojekt.fun:8000/konference/'+details.Konference+'/mistnost/odstranit', null, JSON.stringify(details));

  return error
}

/**
 * Table with rooms - editable
 * @param {*} data data to use
 * @param {*} Koference conference name
 * @returns Html
 */
function GenerateHtml({data, Konference}){
  const [opened, setOpened] = useState(false);
  const [rooms, setRooms] = useState(data);

  const [addFormData, setAddFormData] = useState({
    Kod: "",
    Popis: "",
    Kapacita: "",
    Vybaveni: "",
    Konference: Konference
  });

  const [editFormData, setEditFormData] = useState({
    Kod: "",
    Popis: "",
    Kapacita: "",
    Vybaveni: "",
    Konference: Konference
  });

  const [editRoomKod, setEditRoomKod] = useState(null);

  const handleAddFormChange = (event) => {
    event.preventDefault();

    const fieldName = event.target.getAttribute("name");
    const fieldValue = event.target.value;

    const newFormData = { ...addFormData };
    newFormData[fieldName] = fieldValue;

    setAddFormData(newFormData);
  };

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

    const newRoom = {
        Kod: addFormData.Kod,
        Popis: addFormData.Popis,
        Kapacita: addFormData.Kapacita,
        Vybaveni: addFormData.Vybaveni,
        Konference: Konference
    };

    let error = await Add(newRoom);

    if(!error){
      const newRooms = [...rooms, newRoom];
      setRooms(newRooms);
    }
    else{
      //we can display error
    }

  };

  const handleEditFormSubmit = async (event) => {
    event.preventDefault();

    const editedRoom = {
        Kod: editFormData.Kod,
        Popis: editFormData.Popis,
        Kapacita: editFormData.Kapacita,
        Vybaveni: editFormData.Vybaveni,
        Konference: Konference
    };

    let error = await Update(editedRoom);
    
    if(!error){
      const newRooms = [...rooms];

      const index = rooms.findIndex((room) => room.Kod === editRoomKod);

      newRooms[index] = editedRoom;

      setRooms(newRooms);
      setEditRoomKod(null);
    }
    else{
      //we can display error
    }
    
  };

  const handleEditClick = (event, room) => {
    event.preventDefault();
    setEditRoomKod(room.Kod);

    const formValues = {
        Kod: room.Kod,
        Popis: room.Popis,
        Kapacita: room.Kapacita,
        Vybaveni: room.Vybaveni,
    };

    setEditFormData(formValues);
  };

  const handleCancelClick = () => {
    setEditRoomKod(null);
  };

  const handleDeleteClick = async (roomKod) => {
    const newRooms = [...rooms];

    const index = rooms.findIndex((room) => room.Kod === roomKod);

    let error = await Delete({Kod:roomKod});

    if(!error){
      newRooms.splice(index, 1);

      setRooms(newRooms);
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
                <th>Kod</th>
                <th>Popis</th>
                <th>Vybaveni</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rooms.map((room) => (
                <Fragment>
                {editRoomKod === room.Kod ? (
                  <EditableRow
                    editFormData={editFormData}
                    handleEditFormChange={handleEditFormChange}
                    handleCancelClick={handleCancelClick}
                  />
                ) : (
                  <ReadOnlyRow
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

      <h4>Přidat místnost</h4>
      <form onSubmit={handleAddFormSubmit}>
        <div >
          <label for="Kod" class="form-label">Kód místnosti</label>
          <input id="Kod" class="form-control"
            type="text"
            name="Kod"
            required="required"
            placeholder=""
            onChange={handleAddFormChange}
          />
        </div>
        <div>
          <label for="Popis" class="form-label">Popis</label>
          <input id="Popis" class="form-control"
            type="text"
            name="Popis"
            required=""
            placeholder=""
            onChange={handleAddFormChange}
          />
        </div>        
        <div>
          <label for="Vybavení" class="form-label">Vybavení</label>
          <input id="Vybavení" class="form-control"
            type="text"
            name="Vybaveni"
            required=""
            placeholder=""
            onChange={handleAddFormChange}
          />
        </div>
        
        <div>
          <br />
          <button type="submit" id="btn"
          class="btn btn-round btn-fill btn-outline-success show-hide-btn-sm">Pridať</button>
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
 * Table with rooms only for creator of conference - editable
 * @param {*} Konference conference name
 * @returns Html
 */
function MistnostiTable ({Konference}) {

  let {data, pending, error} = useGet('http://ituprojekt.fun:8000/konference/'+Konference+'/mistnosti', null)

  return(data && 
    <div>
      <GenerateHtml data={data} Konference={Konference}></GenerateHtml>
    </div>
    
    )
};

export default MistnostiTable;