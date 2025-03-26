/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file Footer.jsx
 */
import React from "react";
import "./FooterMap.css";
import Authentificate from "./Authentificate";

/**
 * web app footer
 * @returns Html
 */
function Footer() {
  let isLogin = (Authentificate.isAuth());

  return (
    <div className="Footer">
      <div className="container">
        <h4><center>ITUprojekt.fun | Všechny konference hezky pohromadě!</center></h4><br></br>

        <div className="row">
          <div className="col">
            <h6>MojeKonferece s.r.o.</h6>
            <h6 className="list-unstyled">
              <li>Božetěchova 2/1</li>
              <li>612 00  Brno</li>
              <li>Czech Republic</li>
              <br></br>
              <li>IČO: 00216305</li>
              <li>DIČ: CZ00216305</li>
            </h6>
          </div>

          <div className="col">
            <p className="lightText2">
              <h6>Kontaktujte nás:</h6>
            </p>
            <h6 className="list-unstyled">
              <li>Tel: (+420) 541 141 144</li>
              <li>Tel: (+420) 775 205 000</li>
              <br></br>
              <li>Email: <a href="mailto:info@ituprojekt.fun" class="mailwhite">info@ituprojekt.fun</a></li>
            </h6>
          </div>

          <div className="col">
            <h6 className="list-unstyled">
              <li> </li>
            </h6>
          </div>

          <div className="col">
            <h6 className="lightText2">
              <li><a href="/map" class="mailwhite">Mapa</a></li>
              <li><a href="/rezervaceFind" class="mailwhite">Rezervace</a></li>
              {
                isLogin ?
                  <li><a href="/uzivatele" class="mailwhite">Portfolio uživatelů</a></li>
                  :
                  <></>
              }
              <li><a href="/konference" class="mailwhite">Konference</a></li>
              {
                isLogin ?
                  <li><a href="/novaKonference" class="mailwhite">Přidat konferenci</a></li>
                  :
                  <></>
              }
              {
                isLogin ?
                <li><a href="/uzivatel" class="mailwhite">Profil</a></li>
                  :
                  <li><a href="/signIn" class="mailwhite">Přihlašení</a></li>
              }
            </h6>
          </div>
        </div>

        <hr />
        <div className="row">
          <p className="lightText">
            <h6 className="list-unstyled">
              <li>&copy; 2021 ITUprojekt.fun</li>
            </h6>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Footer;