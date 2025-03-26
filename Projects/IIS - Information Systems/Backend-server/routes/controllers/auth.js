/**
 * @author Tereza Burianova (xburia28)
 * @file Controller for the actions related to authentication.
 */

const sequelize = require('../../config/database.js');
const initModels = require("../../models/init-models");
const models = initModels(sequelize);
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt-nodejs');
const tokenConfig = require('../../config/token')

/**
 * Request POST, route "uzivatel/registrace". Creates a new user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.registrovat = async (req, res) => {
    if (!req.body.Jmeno || !req.body.Prijmeni || !req.body.Email || !req.body.Heslo) {
        return res.status(400).send({message: "Prosím vyplňte pole jméno, příjmení, email a heslo."});
    } else {
        const uzivatelCheck = await models.Uzivatel.findOne({where: {Email: req.body.Email}});
        if (uzivatelCheck) {
            return res.status(422).send({message: "Uživatel s tímto emailem již existuje."});
        }
        if (req.body.Datum_narozeni) {
            // DATE check
            const today = new Date();
            const birth = new Date(req.body.Datum_narozeni);
            if (birth > today) {
                return res.status(422).send({message: "Datum narození nesmí být v budoucnosti."});
            }
        }
        let uzivatel = req.body;
        uzivatel.Role = "uzivatel";
        bcrypt.genSalt(10, (err, salt) => {
            if (err) {return res.status(500).send("Chyba serveru. " + err)};
            bcrypt.hash(req.body.Heslo, salt, null, async (err, hash) => {
                if (err) {return res.status(500).send("Chyba serveru. " + err)};
                uzivatel.Heslo = hash;
                models.Uzivatel.create(uzivatel)
                    .then(data => {
                        res.status(201).send(data);
                    })
                    .catch(err => {
                        return res.status(500).send({message: err.message || "Chyba při vytváření uživatele. " + err});
                    });
            });
        });
        
        
    }
}

/**
 * Request POST, route "uzivatel/prihlaseni". Logs in the user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.prihlasit = async (req, res) => {
    if (!req.body.Email || !req.body.Heslo) {
        return res.status(400).send({message: "Prosím vyplňte pole email a heslo."});
    }
    let uzivatel = await models.Uzivatel.findOne({where: {Email: req.body.Email}});
    if (!uzivatel) {
        return res.status(404).send({message: "Uživatel se zadaným emailem neexistuje."});
    }
    bcrypt.compare(req.body.Heslo, uzivatel.Heslo, (err, isCorrect) => {
        if (err) { return res.status(500).send("Chyba serveru. " + err); }
        else if (!isCorrect) { return res.status(403).send({ message: "Nesprávné heslo." }); }
        else {
            const key = process.env.SECRET || '';
            const token = jwt.sign(uzivatel.toJSON(), key, {expiresIn: '1d'});
            res.send({data: "bearer " + token});
        }
    });
}

/**
 * Request PUT, route "uzivatel/upravit/heslo". Edits the current user's password.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravitHeslo = async (req, res) => {
    if (!req.body.Heslo || !req.body.NoveHeslo) {
        return res.status(400).send({message: "Prosím vyplňte pole heslo a nové heslo."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let uzivatel = await models.Uzivatel.findByPk(tokenDecode.ID);
    if (!uzivatel) {
        return res.status(404).send({message: "Uživatel neexistuje."});
    }
    bcrypt.compare(req.body.Heslo, uzivatel.Heslo, (err, isCorrect) => {
        if (err) { return res.status(500).send("Chyba serveru. " + err); }
        else if (!isCorrect) { return res.status(403).send({ message: "Nesprávné heslo." }); }
        else {
            bcrypt.genSalt(10, (err, salt) => {
                if (err) {return res.status(500).send("Chyba serveru. " + err)};
                bcrypt.hash(req.body.NoveHeslo, salt, null, async (err, hash) => {
                    if (err) {return res.status(500).send("Chyba serveru. " + err)};
                    let data = { ...uzivatel, Heslo: hash };
                    models.Uzivatel.update(data, {where: {ID: tokenDecode.ID}})
                        .then(data2 => {
                            res.send({ID: tokenDecode.ID});
                        })
                        .catch(err => {
                            return res.status(500).send({message: err.message || "Chyba při upravování uživatele."});
                        });
                });
            });
        }
    });
}