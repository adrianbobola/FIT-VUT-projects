/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file PrezentaceEditableRow.jsx
 */
import React from "react";

/**
 * Prezentace row - edit
 */
const PrezentaceEditableRow = ({
  editFormData,
  handleEditFormChange,
  handleCancelClick,
}) => {


  return (
    <div>

    <tr>
      <td>Název</td>
      <td>Konference</td>
      <td>Přednášející</td>
      <td>Popis</td>
      <td>Tagy</td>
      <td>Grafika</td>
    </tr>
    
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
        <input
          type="text"
          required="required"
          placeholder=""
          name="Konference"
          value={editFormData.Konference}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        <input
          type="text"
          required=""
          placeholder=""
          name="Uzivatel"
          value="Vy"
          onChange=""
        ></input>
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
    </tr>

    <tr>
      <td>Soubor</td>
      <td>Místnost</td>
      <td>Schválena</td>
      <td>Začátek čas</td>
      <td>Konec čas</td>
      <td>Poznámky pořadatele</td>
    </tr>

    <tr>
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
        <input
          type="text"
          required=""
          placeholder=""
          name="Mistnost"
          value={editFormData.Mistnost}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        <select
          type="text"
          required=""
          placeholder=""
          name="jeSchvalena"
          value={editFormData.jeSchvalena}
          onChange={handleEditFormChange}
        >
            <option value="true">ano</option>
            <option value="false">ne</option>
        </select>
      </td>

{/*       <td>
        <input
          type="date"
          required=""
          placeholder=""
          name="Datum"
          value={editFormData.Datum}
          onChange=""
        ></input>
      </td> */}

      <td>
        <input
          type="time"
          required=""
          placeholder=""
          name="Zacatek_cas"
          value={editFormData.Zacatek_cas}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        <input
          type="time"
          required=""
          placeholder=""
          name="Konec_cas"
          value={editFormData.Konec_cas}
          onChange={handleEditFormChange}
        ></input>
      </td>

      <td>
        <input
          type="text"
          required=""
          placeholder=""
          name="poznamkyPoradatele"
          value={editFormData.poznamkyPoradatele}
          onChange={handleEditFormChange}
        ></input>
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
    </div>
  );
};

export default PrezentaceEditableRow;