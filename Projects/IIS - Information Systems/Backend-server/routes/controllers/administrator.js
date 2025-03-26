/**
 * @author Adrian Bobola (xbobol00)
 * @file Controller for the system administration.
 */

const sequelize = require('../../config/database.js');
const initModels = require("../../models/init-models");
const models = initModels(sequelize);
const tokenConfig = require('../../config/token');
const bcrypt = require('bcrypt-nodejs');

/**
 * Checks the admin status of the currently logged in user.
 * @param {string} token bearer token
 * @returns True if current user is an admin.
 */
exports.jeAdministrator = async (token) => {
    let user = await models.Uzivatel.findByPk(token.ID);
    if (user.Role == "administrator") {
        return true;
    } else {
        return false;
    }
}

/**
 * Request GET, route "admin/check/:ID". Checks if the user with ID is an admin.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 */
exports.adminStatusID = async (req, res) => {
    models.Uzivatel.findByPk(req.params.ID)
        .then(data => {
            if (!data) {
                return res.status(404).send({message: `Uživatel s ID ${req.params.ID} neexistuje.`});
            }
            if (data.Role == "administrator") {
                res.send({admin: true});
            } else {
                res.status(403).send({admin: false});
            }
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při ověřování role administrátora."});
        });
}

/**
 * Request POST, route "admin/odstranit/:ID". Removes the user as an admin.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.odstranit = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    models.Uzivatel.destroy({where: {ID: req.params.ID}})
        .then(data => {
            return res.send({message: `Uživatel s ID ${req.params.ID} byl odstraněn.`});
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při mazání uživatele."});
        });
}

/**
 * Request PUT, route "admin/upravit/:ID". Edits the user as an admin.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravit = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let admin = await this.jeAdministrator(tokenDecode);
    if (!admin) {
        return res.status(403).send("Pouze administrátor má práva na odstranění uživatelů.");
    }
    models.Uzivatel.update(req.body, {where: {ID: req.params.ID}})
        .then(data => {
            models.Uzivatel.findByPk(req.params.ID)
                .then(data => {
                    res.send(data);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při upravování uživatele."});
                });
            
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při upravování uživatele."});
        });
}

/**
 * Request PUT, route "admin/upravit/heslo/:ID". Edits the password of the user as an admin.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravitHeslo = async (req, res) => {
    if (!req.body.Heslo) {
        return res.status(400).send({message: "Prosím vyplňte pole heslo."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    const admin = await this.jeAdministrator(tokenDecode);
    if (!admin) {
        return res.status(403).send("Pouze administrátor má práva na odstranění uživatelů.");
    }
    let uzivatel = await models.Uzivatel.findByPk(req.params.ID);
    if (!uzivatel) {
        return res.status(404).send({message: "Uživatel neexistuje."});
    }

    bcrypt.genSalt(10, (err, salt) => {
        if (err) {return res.status(500).send("Chyba serveru. " + err)};
        bcrypt.hash(req.body.Heslo, salt, null, async (err, hash) => {
            if (err) {return res.status(500).send("Chyba serveru. " + err)};
            let data = { ...uzivatel, Heslo: hash };
            models.Uzivatel.update(data, {where: {ID: req.params.ID}})
                .then(data2 => {
                    res.send({ID: req.params.ID});
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při upravování uživatele."});
                });
        });
    });

}

