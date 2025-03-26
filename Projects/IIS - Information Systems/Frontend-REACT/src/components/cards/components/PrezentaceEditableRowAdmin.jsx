/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file PrezentaceEditableRowAdmin.jsx
 */
import React from "react";

/**
 * Prezentace row - edit, customized for Admin
 */
const PrezentaceEditableRowAdmin = ({
  editFormData,
  handleEditFormChange,
  handleCancelClick,
}) => {

  return (
    <tr>
      <td>
        {editFormData.Nazev}
      </td>

      <td>
        {editFormData.Konference}
      </td>

      <td>
        {editFormData.Uzivatel}
      </td>

      <td>
        {editFormData.Popis}
      </td>

      <td>
        {editFormData.Tagy}
      </td>

      <td>
        {editFormData.Grafika}
      </td>

      <td>
        {editFormData.Soubor}
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
  );
};

export default PrezentaceEditableRowAdmin;