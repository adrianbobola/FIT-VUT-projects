/**
 * @author Timotej Ponek (xponek00)
 * @file Controller for the action related to conferences.
 */

const sequelize = require('../../config/database.js');
const initModels = require("../../models/init-models");
const models = initModels(sequelize);
const tokenConfig = require('../../config/token');
const auth = require("../../config/isAuthorized");

/**
 * Checks the conference organizer status of the currently logged in user.
 * @param {string} token Bearer token.
 * @param {string} nazev Conference name.
 * @returns Null if the conference doesn't exist, false if user is not organizer, true if user is organizer.
 */
jePoradatel = async (token, nazev) => {
    let konference = await models.Konference.findOne({where: {Nazev: nazev}});
    if (!konference) {
        return null;
    }
    if (konference.Poradatel != token.ID) {
        return false;
    }
    return true;
}

/**
 * Request GET, route "konference/". Gets the list of all conferences.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.konference = async (req, res) => {
    models.Konference.findAll()
        .then(data => {
            if (!data) {
                return res.status(204).send({message: "Nebyly vytvořeny žádné konference."});
            }
            let newData = data.map(a => ({...a.dataValues, oblibena: null}));
            setTimeout((() => {
                let tokenDecode = tokenConfig.getData(req, res);
                if (tokenDecode.ID) {
                models.R_Oblibene_Konference.findAll({where: {ID: tokenDecode.ID}})
                .then(data2 => {
                        data2 = data2.map(objekt => objekt.Nazev);
                        newData.forEach((konf) => {
                            if (data2.includes(konf.Nazev)) {
                                konf.oblibena = true;
                            } else {
                                konf.oblibena = false;
                            }
                        })
                        res.send(newData);
                    })
                .catch(err => {
                        return res.status(500).send({message: err.message || "Chyba při ověřování oblíbených konferencí."});
                });
            } else {
                newData.forEach((konf) => {
                    konf.oblibena = null;
                })
                res.send(newData);
            }

      }), 1000)
    })
    .catch(err => {
      return res.status(500).send({ message: err.message || "Chyba při zobrazování konferencí." });
    });
}
/**
 * Request POST, route "konference/vytvorit". Creates a new conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.vytvoritKonferenci = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }

    const konference = req.body;
    
    let tokenDecode = tokenConfig.getData(req, res);

    konference.Poradatel = tokenDecode.ID;
    konference.ZbyvajiciKapacita = req.body.Kapacita;
    konference.Konec_datum = req.body.Zacatek_datum;
    if (req.body.Zacatek_cas >= req.body.Konec_cas) {
        return res.status(422).send({message: "Konference začíná ve stejný čas nebo později než končí."});
    }
    if (req.body.Zacatek_datum) {
        // DATE check
        const today = new Date();
        const start = new Date(req.body.Zacatek_datum);
        if (start < today) {
            return res.status(422).send({message: "Konference se nesmí konat v minulosti."});
        }
    }
    models.Konference.create(konference)
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při vytváření konference."});
        });
}

/**
 * Request GET, route "konference/:Nazev". Gets all the information about one conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitKonferenci = async (req, res) => {
    models.Konference.findByPk(req.params.Nazev)
        .then(data => {
            if (!data) {
                return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování konference."});
        });
}

/**
 * Request PUT, route "konference/:Nazev/upravit". Edits a conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravitKonferenci = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let state = await jePoradatel(tokenDecode, req.params.Nazev);
    if (state == null) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    } else if (state !==true) {
        return res.status(403).send({message: `Pouze pořadatel konference s názvem ${req.params.Nazev} je oprávněn dělat změny.`});
    }
    if (req.body.Zacatek_cas >= req.body.Konec_cas) {
        return res.status(422).send({message: "Konference začíná ve stejný čas nebo později než končí."});
    }
    let data = { ...req.body, Nazev: undefined, Poradatel: undefined, Konec_datum: undefined };
    models.Konference.update(data ,{where: {Nazev: req.params.Nazev}})
        .then(data => {
            models.Konference.findByPk(req.params.Nazev)
                .then(data2 => {
                    res.send(data2);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při upravování konference."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při upravování konference."});
        });
}

/**
 * Request POST, route "konference/:Nazev/novaMistnost". Creates a new room for the conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.pridatMistnost = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let state = await jePoradatel(tokenDecode, req.params.Nazev);
    if (state == null) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    } else if (state !==true) {
        return res.status(403).send({message: `Pouze pořadatel konference s názvem ${req.params.Nazev} je oprávněn dělat změny.`});
    }

    const mistnost = req.body;
    mistnost.Konference = req.params.Nazev;
    models.Mistnost.create(mistnost)
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při vytváření místnosti."});
        });
}

/**
 * Request PUT, route "konference/:Nazev/mistnost/upravit". Edits a room.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravitMistnost = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let state = await jePoradatel(tokenDecode, req.params.Nazev);
    if (state == null) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    } else if (state !==true) {
        return res.status(403).send({message: `Pouze pořadatel konference s názvem ${req.params.Nazev} je oprávněn dělat změny.`});
    }
    let mistnost = { ...req.body, Kod: undefined, Konference: req.params.Nazev }
    models.Mistnost.update(mistnost, {where: {Kod: req.body.Kod}})
        .then(data => {
            models.Mistnost.findByPk(req.body.Kod)
                .then(data2 => {
                    res.send(data2);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při upravování místnosti."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při úpravě místnosti."});
        });
}

/**
 * Request POST, route "konference/:Nazev/mistnost/odstranit". Removes a room.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.odstranitMistnost = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let state = await jePoradatel(tokenDecode, req.params.Nazev);
    if (state == null) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    } else if (state !==true) {
        return res.status(403).send({message: `Pouze pořadatel konference s názvem ${req.params.Nazev} je oprávněn dělat změny.`});
    }

    models.Mistnost.destroy({where: {Kod: req.body.Kod}})
        .then(data => {
            return res.send({message: `Místnost s kódem ${req.body.Kod} byla odstraněna.`});
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při mazání místnosti."});
        });
}

/**
 * Request GET, route "konference/:Nazev/mistnosti". Gets all rooms.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.mistnosti = async (req, res) => {
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    models.Mistnost.findAll({where: {Konference: konference.Nazev}})
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování místností."});
        });
}
