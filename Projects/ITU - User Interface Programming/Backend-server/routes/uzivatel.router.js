/**
 * @author Timotej Ponek (xponek00)
 * @file Router for the requests related to users.
 */

const express = require('express');
const router = express.Router();
const authC = require("./controllers/auth");
const uzivatelC = require("./controllers/uzivatel");
const prispevkyC = require("./controllers/prispevek");
const rezervaceC = require("./controllers/rezervace");
const auth = require("../config/isAuthorized");

router.post("/registrace", authC.registrovat);
router.post("/prihlaseni", authC.prihlasit);
router.put("/upravit", auth.isLoggedIn, uzivatelC.upravit);
router.get("/rezervace", auth.isLoggedIn, rezervaceC.zobrazitUzivatel);
router.put("/upravit/heslo", auth.isLoggedIn, authC.upravitHeslo);
router.post("/odstranit", auth.isLoggedIn, uzivatelC.odstranit);
router.get("/prispevky", auth.isLoggedIn, prispevkyC.uzivatelAktualniPrispevky);
router.get("/poradatel", auth.isLoggedIn, uzivatelC.zobrazitAktualniKonference);
router.get("/:ID/poradatel", uzivatelC.zobrazitKonference);
router.get("/seznam", uzivatelC.seznam);
router.get("/:ID/prispevky", prispevkyC.uzivatelPrispevky);
router.get("/:ID", uzivatelC.zobrazit);
router.get("/", auth.isLoggedIn, uzivatelC.zobrazitAktualni);

module.exports = router;