/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file PersonListDelete.jsx
 */

 import React, { useEffect, useState } from "react";
 import axios from "axios";
 import Search from "./cards/components/Search";
 
 export default class PersonListDelete extends React.Component {
     state = {
         ID: 0,
         persons: [],
     };
 
     componentDidMount() {
         axios.get(`http://ituprojekt.fun:8000/uzivatel/seznam`)
             .then(res => {
                 console.log(res);
                 const persons = res.data;
                 this.setState({ persons });
             }).catch(err => {
                 console.error(err);
             });
     }
 
     handleChange = event => {
         this.setState({ ID: event.target.value });
     };
 
     handleSubmit = event => {
         event.preventDefault();
 
         axios.post(`http://ituprojekt.fun:8000/admin/odstranit/${this.state.ID}`)
             .then(res => {
                 console.log(res);
                 console.log(res.data);
                 axios.get(`http://ituprojekt.fun:8000/uzivatel/seznam`)
                     .then(res => {
                         console.log(res);
                         const persons = res.data;
                         this.setState({ persons });
                     }).catch(err => {
                         console.error(err);
                     });
             }).catch(err => {
                 console.error(err);
             });
     };
 
     render() {
         return (
             <div>
                 <form onSubmit={this.handleSubmit}>
                     <label>
                         <h2>Vybrany uzivatel s ID:</h2>
                         <h3>{this.state.ID}</h3>
                         <input type="number" name="ID" onChange={this.handleChange} />
                     </label>
                     <button type="submit" class="btn btn-round btn-fill btn-danger show-hide-btn-sm">
                         <i class="nc-icon nc-stre-up"></i>
                         Smazat
                     </button>
                 </form><br></br><br></br>
                 <Search data={this.state.persons} />
             </div>
         )
     }
 }