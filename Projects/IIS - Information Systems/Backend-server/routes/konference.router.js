/**
 * @author Timotej Ponek (xponek00)
 * @author Tereza Burianova (xburia28)
 * @file Router for the requests related to conferences.
 */

const express = require('express');
const router = express.Router();
const authC = require("./controllers/auth")
const konferenceC = require("./controllers/konference")
const prispevekC = require("./controllers/prispevek")
const rezervaceC = require("./controllers/rezervace")
const oblibeneC = require("./controllers/oblibene")
const auth = require("../config/isAuthorized")

//* BASIC OPERATIONS
router.post("/vytvorit", auth.isLoggedIn, konferenceC.vytvoritKonferenci);
router.put("/:Nazev/upravit", auth.isLoggedIn, konferenceC.upravitKonferenci);

//* CONTRIBUTIONS
router.post("/:Nazev/novyPrispevek", auth.isLoggedIn, prispevekC.vytvoritPrispevek);
router.get("/:Nazev/prispevky", prispevekC.konferencePrispevky);
router.get("/:Nazev/prispevky/schvalene", prispevekC.konferencePrispevkyS);
router.get("/:Nazev/prispevky/neschvalene", prispevekC.konferencePrispevkyN);
router.put("/:Nazev/prispevky/:ID/upravit", auth.isLoggedIn, prispevekC.upravit);
router.post("/:Nazev/prispevky/:ID/odstranit", auth.isLoggedIn, prispevekC.odstranit);
router.put("/:Nazev/prispevky/:ID/schvalit", auth.isLoggedIn, prispevekC.schvalit);

//* ROOMS
router.post("/:Nazev/novaMistnost", auth.isLoggedIn, konferenceC.pridatMistnost);
router.get("/:Nazev/mistnosti", konferenceC.mistnosti);
router.put("/:Nazev/mistnost/upravit", auth.isLoggedIn, konferenceC.upravitMistnost);
router.post("/:Nazev/mistnost/odstranit", auth.isLoggedIn, konferenceC.odstranitMistnost);
router.get("/:Nazev/:Mistnost/prispevky", prispevekC.mistnostPrispevky);

//* RESERVATIONS
router.post("/:Nazev/novaRezervace", auth.isLoggedIn, rezervaceC.vytvoritAktualni);
router.post("/:Nazev/novaRezervace/nereg", rezervaceC.vytvoritBezReg);
router.post("/:Nazev/novaRezervace/reg", rezervaceC.vytvoritSReg);
router.put("/:Nazev/rezervace/:ID/potvrdit", auth.isLoggedIn, rezervaceC.potvrdit);
router.post("/:Nazev/rezervace/:ID/odstranit", auth.isLoggedIn, rezervaceC.odstranit);
router.get("/:Nazev/rezervace/:ID", rezervaceC.zobrazit);
router.get("/rezervace/:ID", rezervaceC.zobrazitID);
router.get("/:Nazev/rezervace/", auth.isLoggedIn, rezervaceC.zobrazitKonference);

//* FAVOURITES
router.get("/oblibene", auth.isLoggedIn, oblibeneC.zobrazitOblibene);
router.post("/:Nazev/oblibene/pridat", auth.isLoggedIn, oblibeneC.pridatOblibene);
router.post("/:Nazev/oblibene/odebrat", auth.isLoggedIn, oblibeneC.odebratOblibene);
router.get("/:Nazev/oblibene/stav", auth.isLoggedIn, oblibeneC.jeOblibena);

//* VIEWS
router.get("/:Nazev", konferenceC.zobrazitKonferenci);
router.get("/", konferenceC.konference);

module.exports = router;
