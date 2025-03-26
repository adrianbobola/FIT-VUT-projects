/**
 * @author Adrian Bobola (xbobol00)
 * @file Router for the requests related to administration.
 */

const express = require('express');
const router = express.Router();
const adminC = require("./controllers/administrator")
const auth = require("../config/isAuthorized")

router.post("/odstranit/:ID", adminC.odstranit);
router.put("/upravit/:ID", auth.isLoggedIn, adminC.upravit);
router.put("/upravit/heslo/:ID", auth.isLoggedIn, adminC.upravitHeslo);
router.get("/check/:ID", adminC.adminStatusID);

module.exports = router;
