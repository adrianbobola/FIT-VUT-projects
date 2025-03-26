/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file MistnostiReadRow.jsx
 */
import React from "react";
import { useNavigate } from "react-router";

/**
 * Mistnosti row - read only
 */
const MistnostiReadRow = ({ data, handleEditClick, handleDeleteClick }) => {
  const navigate = useNavigate();
  return (
    <tr>
      <td>{data.Kod}</td>
      <td>{data.Popis}</td>
      <td>{data.Vybaveni}</td>
      <td>
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

export default MistnostiReadRow;