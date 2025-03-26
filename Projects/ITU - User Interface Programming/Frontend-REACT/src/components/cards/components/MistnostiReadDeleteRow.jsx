/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file MistnostiReadDeleteRow.jsx
 */
import React from "react";
import { useNavigate } from "react-router";

/**
 * Mistnosti row - read and delete
 */
const MistnostiReadDeleteRow = ({ data, handleEditClick, handleDeleteClick }) => {
  const navigate = useNavigate();
  return (
    <tr>
      <td>{data.Kod}</td>
      <td>{data.Popis}</td>
      <td>{data.Vybaveni}</td>
      <td>
        <button
          type="button" class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
          onClick={(event) => handleEditClick(event, data)}
        >
          Uprav
        </button>
        <button 
          type="button" class="btn btn-round btn-fill btn-danger show-hide-btn-sm"
          onClick={() => handleDeleteClick(data.Kod)}
        >
          Zmaž
        </button>

        <button 
          type="button" class="btn btn-round btn-fill btn-secondary show-hide-btn-sm"
          onClick={() => navigate("/konference/"+data.Konference+'/'+data.Kod)}
        >
          Zobraz prezentace
        </button>
      </td>
    </tr>
  );
};

export default MistnostiReadDeleteRow;