/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file App.js
 */

import './App.css';
import "./index.css";
import { BrowserRouter as Router, Route, Routes, useNavigate } from "react-router-dom";
import {
  KonferenceList,
  KonfereceDetail,
  KonferenceMistnostDetail,
  Navigation,
  Rezervace,
  PrispevekNew,
  KonferenceNew,
  SignIn,
  PrezentaceListReadOnly,
  PrezentaceUserList,
  KonferenceDetailNotRegistered,
  RezervaceFind,
  UserProfile,
  Harmonogram,
  Users
} from "./components";

import Auth from './components/Authentificate';
import ProtectedRoute, {UnprotectedRoute} from './components/AuthRoute';
import CurrentUserProfile from './components/routes/CurrentUserProfile';
import Admin from './components/routes/Admin';
import Footer from './components/Footer';
import Map from './components/Map';

import React from 'react';
import { Helmet } from 'react-helmet';

function App() {

  return (
  <div>
      <Helmet>
        <title>Moje Konference</title>
      </Helmet>

  <Router>
    <Navigation />
    <Routes>
      <Route path="/" element={<UnprotectedRoute><SignIn /></UnprotectedRoute>} />

      {!Auth.authentificated &&
        <Route path="/signIn" element={<SignIn/>}/>
      }
      <Route path="/konference" element={<KonferenceList url={'http://ituprojekt.fun:8000/konference/'} />}/>

      <Route path="/map" exact exact element={ <Map/> } />

      <Route path ="/admin" exact exact element={ <ProtectedRoute> <Admin /> </ProtectedRoute> } />

      <Route path="/novaKonference" element={ <ProtectedRoute>  <KonferenceNew /> </ProtectedRoute> } />
      <Route path="/uzivatel" exact element={<ProtectedRoute> <CurrentUserProfile token={Auth.token}/> </ProtectedRoute>}/>

      <Route path="/uzivatel/prezentace" exact element={<ProtectedRoute> <PrezentaceUserList token={Auth.token}/> </ProtectedRoute>}/>
      <Route path="/uzivatel/konference" exact element={<ProtectedRoute> <KonferenceList url={'http://ituprojekt.fun:8000/uzivatel/poradatel'}/> </ProtectedRoute>}/>

      <Route path="/uzivatel/:id" exact element={<ProtectedRoute> <UserProfile/> </ProtectedRoute>}/>
      <Route path="/uzivatele" exact element={<ProtectedRoute> <Users/> </ProtectedRoute>}/>

      <Route path="/konference/:id" exact element={ <ProtectedRoute> <KonfereceDetail /> </ProtectedRoute> } />
      <Route path="/konference/notRegistered/:id" element={ <KonferenceDetailNotRegistered /> } />
      <Route path="/konference/:id/harmonogram" exact element={ <Harmonogram /> } />
      
      <Route path="/konference/:id/rezervace" exact element={ <Rezervace /> } />
      <Route path="/rezervaceFind" exact element={ <RezervaceFind /> } />

      <Route path="/konference/:id/:kod" exact exact element={ <ProtectedRoute> <KonferenceMistnostDetail /> </ProtectedRoute> } />
      <Route path="/konference/:id/novyPrispevek" element={ <ProtectedRoute> <PrispevekNew/> </ProtectedRoute> } />

      <Route path="/konference/:id/prispevkySchvalene" element={ <ProtectedRoute> <PrezentaceListReadOnly/> </ProtectedRoute> } />

    </Routes>
  </Router>
  <Footer/>
  </div>
  );
}

export default App;
