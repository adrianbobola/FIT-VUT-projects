/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file Users.jsx
 */
import React, {useState} from 'react';
import { useGet } from '../../static/Loaders';
import UserDetailPortfolio from '../cards/UserDetailPortfolio';

/**
 * 
 * @param {*} datas data to work with
 * @returns 
 */
function InnerHtml({datas}){

  const [filter1, setFilter1] = useState(null)
  const [filter2, setFilter2] = useState(null)
  const [filter3, setFilter3] = useState(null)
  const [filter4, setFilter4] = useState(null)    

  const data = (datas.filter(uzivatel =>
      (filter1 ? uzivatel.ID === Number(filter1) : true) &&
      (filter2 ? uzivatel.Email.toLowerCase().includes(filter2.toLowerCase()) : true) &&
      (filter3 ? uzivatel.Jmeno.toLowerCase().includes(filter3.toLowerCase()) : true) &&
      (filter4 ? uzivatel.Prijmeni.toLowerCase().includes(filter4.toLowerCase()) : true)
  ))

  return(
      <div class="col-12">

          <div class="content container-fluid">
              <div class="row mb-3 " style={{marginTop: 20}}>
                  <div class="col-12 themed-grid-col">
          
          <div class="input-group">

          <div class="form-outline" style={{marginRight: 20}}>
              <h2>Filtr: </h2>
          </div>

          <div class="form-outline">
              <label class="form-label" for="form1">Zadej id</label>
              <input type="search" id="form1" class="form-control" 
              onChange={(e) => setFilter1(e.target.value)}/>
          </div>

          <div class="form-outline">
              <label class="form-label" for="form1">Zadej email</label>
              <input type="search" id="form1" class="form-control" 
              onChange={(e) => setFilter2(e.target.value)}/>
          </div>

          <div class="form-outline">
              <label class="form-label" for="form1">Zadej jméno</label>
              <input type="search" id="form1" class="form-control" 
              onChange={(e) => setFilter3(e.target.value)}/>
          </div>

          <div class="form-outline">
              <label class="form-label" for="form1">Zadej přijmení</label>
              <input type="search" id="form1" class="form-control" 
              onChange={(e) => setFilter4(e.target.value)}/>
          </div>
                  </div>
              </div>
          </div>
          </div>

        {
        data &&
        data.map((uzivatel) => (
            <div className={uzivatel} key={uzivatel.ID}>
                <UserDetailPortfolio uzivatel={uzivatel} />
            </div>
            )
         )
        }

        {
        !data  &&
        <div className="">
            <h2>Zadanému filtru neodpovídá žadný uživatel</h2>
        </div>
        }

      </div>
  )
}

/**
 * Returns list of user profiles
 * @returns 
 */
function Users() {

    let { data, pending, error } = useGet('http://ituprojekt.fun:8000/uzivatel/seznam', null)
    
  return (
    <div class="card">
    { error && <div>{ error }</div> }
    { pending && 

    <div class="container-fluid content">
        <div class="row mb-3 justify-content-center">
            <div>Loading...
                <div class="spinner-border text-secondary" role="status">
                </div>
            </div> 
        </div>
    </div>}
    {
        data &&
        <InnerHtml datas={data}/>
    }
    </div>
  )
}

export default Users;