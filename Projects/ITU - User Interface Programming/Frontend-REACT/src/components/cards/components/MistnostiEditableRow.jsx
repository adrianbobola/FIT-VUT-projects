/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file MistnostiEditableRow.jsx
 */
import React from "react";

/**
 * Mistnosti row - read and delete
 */
const MistnostiEditableRow = ({
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
          name="Kod"
          value={editFormData.Kod}
          onChange={handleEditFormChange}
        ></input>
      </td>
      <td>
        <input
          type="text"
          required=""
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
          name="Vybaveni"
          value={editFormData.Vybaveni}
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

export default MistnostiEditableRow;