/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file PrezentaceUserList.jsx
 */
import React from "react";
import PrezentaceUserEdit from "../cards/PrezentaceTableUserEdit";

/**
 * Returns table with presentations of currently logged in user
 */
function PrezentaceUserList() {

return (

    <div className="Konference">
        <div class="content container-fluid">
            <div class="row mb-3 justify-content-center" style={{marginTop: 20}}>
                <div class="col-12 themed-grid-col">
                    
                {
                    
                    <div>
                        <div class="card">
                            <div class="card-header card-header-flex">
                                <h3 class="card-title text-bold"> Prispevky v konferenciach: </h3>

                                <PrezentaceUserEdit url={'http://ituprojekt.fun:8000/uzivatel/prispevky'}/>

                            </div>
                        </div>
                    </div>
                }
                

                </div>
            </div>
        </div>
    </div>
    
  );
}

export default PrezentaceUserList;
