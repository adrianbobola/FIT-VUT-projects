/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file RezervacePotvrditRow.jsx
 */
import React from "react";

/**
 * Rezervace row that provides ability to confirm reservation
 */
const RezervacePotvrditRow = ({ data, handleEditClick, handleDeleteClick, poradatel }) => {
  return (
    <tr>
        {poradatel &&
      <td>{data.Konference}</td>}
      <td>{data.Email}</td>
      <td>{data.Datum_vytvoreni}</td>
      <td>{data.Pocet_vstupenek}</td>
      <td>{data.Celkova_cena}</td>
      <td>{data.Stav}</td>
      {poradatel &&
      <td>
        <button
          type="button" class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
          onClick={(event) => handleEditClick(event, data.ID)}
        >
          Potvrdit
        </button>
        <button 
          type="button" class="btn btn-round btn-fill btn-danger show-hide-btn-sm"
          onClick={() => handleDeleteClick(data.ID)}
        >
          Zrušit
        </button>
      </td>
        }
    </tr>
  );
};

export default RezervacePotvrditRow;