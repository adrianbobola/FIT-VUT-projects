/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file PrezentaceEditableRowUser.jsx
 */
import React from "react";

/**
 * Prezentace row - edit, customized for User
 */
const PrezentaceEditableRowUser = ({
  editFormData,
  handleEditFormChange,
  handleCancelClick,
}) => {
  return (
    <tr>
      <td>
        <input
          type="text"
          required="required"
          placeholder=""
          name="Nazev"
          value={editFormData.Nazev}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        {editFormData.Konference}
      </td> 

     
      <td>
        {editFormData.Uzivatel}
      </td>


      <td>
        
        <input
          type="text"
          required="required"
          placeholder=""
          name="Popis"
          value={editFormData.Popis}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        
        <input
          type="text"
          required=""
          placeholder=""
          name="Tagy"
          value={editFormData.Tagy}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        <input
          type="text"
          required=""
          placeholder=""
          name="Grafika"
          value={editFormData.Grafika}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        <input
          type="text"
          required=""
          placeholder=""
          name="Soubor"
          value={editFormData.Soubor}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        {editFormData.Mistnost}
      </td>

      <td>
        {editFormData.jeSchvalena? "ano" : "ne"}
      </td>

      <td>
        {editFormData.Zacatek_cas}
      </td>

      <td>
        {editFormData.Konec_cas}
      </td>

      <td>
        {editFormData.poznamkyPoradatele}
      </td>

      <td>
        <button type="submit"
            class="btn btn-round btn-fill btn-success show-hide-btn-sm">Uložit</button>
        <button type="button" onClick={handleCancelClick}
            class="btn btn-round btn-fill btn-outline-danger show-hide-btn-sm">
          Zrušit
        </button>
      </td>
    </tr>
  );
};

export default PrezentaceEditableRowUser;