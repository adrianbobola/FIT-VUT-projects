/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file Search.jsx
 */
import React from "react";
import { useState } from "react";
import YesAdmin from "../../cards/YesAdmin";

function Search({ data }) {
  const [filteredData, setFilteredData] = useState([]);
  const [filteredDataByName, setFilteredDataByName] = useState([]);
  const [searchWord, setSearchWord] = useState("");
  const [searchByName, setSearchByName] = useState(false);
  const [nullInput, setNullInput] = useState(true);
  const data2 = data;

  const handleFilter = (event) => {
    const searchWord = event.target.value;
    setSearchWord(searchWord);
    const newFilter = data.filter((value) => {
      return value.Email.toLowerCase().includes(searchWord.toLowerCase());
    });
    const newFilterByName = data2.filter((value) => {
      return value.Prijmeni.toLowerCase().includes(searchWord.toLowerCase());
    });

    if (searchWord === "") {
      setFilteredData([]);
      setFilteredDataByName([]);
      setNullInput(true);
    } else {
      setFilteredData(newFilter);
      setFilteredDataByName(newFilterByName);
      setNullInput(false);
    }
  };

  return (
    <div className="search">
      <div className="searchInputs">

        {searchByName && (
          <div>
            <h3>Vyhladavanie podla: mena</h3>
            <input
              type="text"
              placeholder="Zadajte meno..."
              value={searchWord}
              onChange={handleFilter}
            />
          </div>
        )}

        {!searchByName && (
          <div>
            <h3>Vyhladavanie podla: emailu</h3>
            <input
              type="text"
              placeholder="Zadajte email..."
              value={searchWord}
              onChange={handleFilter}
            />
          </div>
        )}

      </div>
      <button class="btn btn-round btn-fill btn-secondary show-hide-btn-sm"
        onClick={() => setSearchByName(!searchByName)}>
        <i class="nc-icon nc-stre-up"></i>
        {searchByName ? "Podla emailu" : "Podla mena"}
      </button>

      {(filteredData.length != 0 && !searchByName) && (
        <div className="dataResult">
          {filteredData.map((value, key) => {
            return (
              <div className="uzivatelia" key={value.ID}>
                <YesAdmin allUsers={value} showEmail={true} />
              </div>
            );
          })}
        </div>
      )}

      {(filteredData.length == 0 && nullInput && !searchByName) && (
        <div className="dataResult">
          {
            data && data.map((value, key) => {
              return (
                <div className="uzivatelia" key={value.ID}>
                  <YesAdmin allUsers={value} showEmail={true} />
                </div>
              );
            })}
        </div>
      )}

      {(filteredDataByName.length != 0 && searchByName) && (
        <div className="dataResult">
          {filteredDataByName.map((value, key) => {
            return (
              <div className="uzivatelia" key={value.ID}>
                <YesAdmin allUsers={value} showEmail={false} />
              </div>
            );
          })}
        </div>
      )}

      {(filteredDataByName.length == 0 && nullInput && searchByName) && (
        <div className="dataResult">
          {
            data2 && data2.map((value, key) => {
              return (
                <div className="uzivatelia" key={value.ID}>
                  <YesAdmin allUsers={value} showEmail={false} />
                </div>
              );
            })}
        </div>
      )}

    </div>
  );
}
export default Search;