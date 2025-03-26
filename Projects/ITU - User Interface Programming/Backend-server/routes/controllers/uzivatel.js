/**
 * @author Timotej Ponek (xponek00)
 * @file Controller for the actions related to users (except the authentication).
 */

const sequelize = require('../../config/database.js');
const initModels = require("../../models/init-models");
const models = initModels(sequelize);
const tokenConfig = require('../../config/token')

/**
 * Request GET, route "uzivatel/seznam". Gets a list of all users.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.seznam = async (req, res) => {
    models.Uzivatel.findAll()
        .then(data => {
            if (!data) {
                return res.status(204).send({message: "Nebyli zaregistrováni žádní uživatelé."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování uživatelů."});
        });
}

/**
 * Request GET, route "uzivatel/:ID". Gets information about a user. 
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazit = async (req, res) => {
    models.Uzivatel.findByPk(req.params.ID)
        .then(data => {
            if (!data) {
                return res.status(404).send({message: `Uživatel s ID ${req.params.ID} neexistuje.`});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování uživatele."});
        });
}

/**
 * Request GET, route "uzivatel/". Gets information about the current user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitAktualni = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    models.Uzivatel.findByPk(tokenDecode.ID)
        .then(data => {
            if (!data) {
                return res.status(404).send({message: `Uživatel není přihlášen.`});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování uživatele."});
        });
}

/**
 * Request POST, route "uzivatel/odstranit". Removes the current user. 
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.odstranit = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    models.Uzivatel.destroy({where: {ID: tokenDecode.ID}})
        .then(data => {
            return res.send({message: `Uživatel s emailovou adresou ${tokenDecode.Email} byl odstraněn.`});
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při mazání uživatele."});
        });
}

/**
 * Request PUT, route "uzivatel/upravit". Edits the current user. 
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravit = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    if (req.body.Datum_narozeni) {
        // DATE check
        const today = new Date();
        const birth = new Date(req.body.Datum_narozeni);
        if (birth > today) {
            return res.status(422).send({message: "Datum narození nesmí být v budoucnosti."});
        }
    }
    let data = { ...req.body, Heslo: undefined, Email: undefined };
    models.Uzivatel.update(data, {where: {ID: tokenDecode.ID}})
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při upravování uživatele."});
        });
}

/**
 * Request GET, route "uzivatel/poradatel". Gets all conferences organized by the current user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitAktualniKonference = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    models.Konference.findAll({where: {Poradatel: tokenDecode.ID}})
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování konferencí."});
        });
}

/**
 * Request GET, route "uzivatel/:ID/poradatel". Gets all conferences organized by a user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitKonference = async (req, res) => {
    let uzivatel = await models.Uzivatel.findByPk(req.params.ID);
    if (!uzivatel) {
        return res.status(404).send({message: `Uživatel s ID ${req.params.ID} neexistuje.`});
    }
    models.Konference.findAll({where: {Poradatel: uzivatel.ID}})
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování konferencí."});
        });
}

