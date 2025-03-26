/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file KonferenceCardNotRegistered.jsx
 */
import React from 'react';
import { NavLink } from "react-router-dom";

/**
 * Class representing card containg conference details and other tabs related to conference 
 * -> not registereded/logged in user
 */
class KonferenceCard extends React.Component{
    state = {
        open: false
    }

    konference = this.props.data;

    render(){

        let card;
        let konference = this.props.data;
        const opened = this.state.open;

        if (opened){
            card = (
        <div className="cardBody">
            <nav id="navbar" class="navbar navbar-light bg-light px-3">
                <a class="navbar-brand"></a>
                <ul class="nav nav-pills">
                    <li class="nav-item">
                    <li class="nav-item">
                        <NavLink className="nav-link btn-warning" to={{
                            pathname: "/konference/"+konference.Nazev+"/rezervace",
                            userProps: konference
                        }}>
                            Rezervovat vstupenku
                        </NavLink>
                    </li>
                    </li>
                    <li class="nav-item">
                        <NavLink className="nav-link btn-outline-primary" to={
                            "/konference/"+konference.Nazev+"/harmonogram"}>
                            Harmonogram
                        </NavLink>
                    </li>
                    <li>
                        <NavLink className="nav-link btn-primary" to={"/konference/notRegistered/"+konference.Nazev}>
                            Zobraz mistnosti a příspěvky
                        </NavLink>
                    </li>
                </ul>
            </nav>

            <div class="bg-light px-3">
                <p>Popis: {konference.Popis}</p>
                <p>Obor: {konference.Obor}</p>
                <p>Zeme: {konference.Zeme}</p>
                <p>Mesto: {konference.Mesto}</p>
                <p>Misto: {konference.Misto}</p>
                <p>Zacatek: {konference.Zacatek_datum}, {konference.Zacatek_cas}</p>
                <p>Konec: {konference.Konec_datum}, {konference.Konec_cas}</p>
                <p>Poplatek: {konference.Poplatek}</p>
                <p>Vstupné: {konference.Cena_vstup}</p>
                <p>Kapacita: {konference.Kapacita}</p>
                <p>Další údaje: {konference.Doplnujici_udaje}</p>
            </div>

        </div>)
        } else {
            card = null;
        }

        return (
        <div class="card">
            <div class="card-header card-header-flex">
                <h3 class="card-title text-bold"> {konference.Nazev} </h3>
                <button class="btn btn-round btn-fill btn-primary show-hide-btn-sm"
                        onClick={(() => this.setState({ open: !this.state.open }))}>
                    <i class="nc-icon nc-stre-up"></i>
                    {opened ? "Skrýt" : "Zobrazit"}
                </button>
            </div>
    
            {card}

        </div>
        )
    }

}

export default KonferenceCard;