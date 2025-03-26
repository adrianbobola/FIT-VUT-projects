/**
 * @author Tereza Burianova (xburia28)
 * @file Controller for the actions related to contributions.
 */

const sequelize = require('../../config/database.js');
const initModels = require("../../models/init-models");
const models = initModels(sequelize);
const tokenConfig = require('../../config/token');

/**
 * Request POST, route "konference/:Nazev/novyPrispevek". Creates a new contribution.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.vytvoritPrispevek = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    const prezentace = req.body;
    models.Konference.findByPk(req.params.Nazev)
        .then(data => {
            if (!data) {
                return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
            }
            prezentace.Konference = data.Nazev;
            let tokenDecode = tokenConfig.getData(req, res);
            prezentace.Uzivatel = tokenDecode.ID;
            prezentace.Mistnost = undefined;
            prezentace.jeSchvalena = false;
            prezentace.Zacatek_cas = undefined;
            prezentace.Konec_cas = undefined;

            models.Prezentace.create(prezentace)
                .then(data => {
                    res.send(data);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při vytváření příspěvku."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování konference."});
        });
}

/**
 * Request PUT, route "konference/:Nazev/prispevky/:ID/upravit". Edits a contribution.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.upravit = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let prispevek = await models.Prezentace.findByPk(req.params.ID);
    if (!prispevek) {
        return res.status(404).send({message: `Příspěvek s ID ${erq.params.ID} neexistuje.`});
    }
    if (prispevek.Uzivatel != tokenDecode.ID) {
        return res.status(403).send({message: `Pouze autor příspěvku je oprávněn dělat změny.`});
    }
    if (req.body.Zacatek_cas && req.body.Konec_cas) {
        if (req.body.Zacatek_cas >= req.body.Konec_cas) {
            return res.status(422).send({message: "Příspěvek začíná ve stejnou dobu nebo později než končí."});
        }
    }
    let data = {...req.body, Uzivatel:undefined, Datum:undefined};
    models.Prezentace.update(data, {where: {ID: req.params.ID}})    
        .then(data => {
            models.Prezentace.findByPk(req.params.ID)
                .then(data => {
                    res.send(data);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při upravování příspěvku."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při upravování konference."});
        });
}

/**
 * Request POST, route "konference/:Nazev/prispevky/:ID/odstranit". Removes a contribution.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.odstranit = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let prispevek = await models.Prezentace.findByPk(req.params.ID);
    if (!prispevek) {
        return res.status(404).send({message: `Příspěvek s ID ${erq.params.ID} neexistuje.`});
    }
    if (prispevek.Uzivatel != tokenDecode.ID) {
        return res.status(403).send({message: `Pouze autor příspěvku je oprávněn dělat změny.`});
    }
        
    models.Prezentace.destroy({where: {ID: req.params.ID}})    
        .then(data => {
            return res.send({message: `Příspěvek s ID ${req.params.ID} byl odstraněn.`});
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při upravování konference."});
        });
}

/**
 * Request GET, route "uzivatel/:ID/prispevky". Gets all user's contributions.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.uzivatelPrispevky = async (req, res) => {
    models.Prezentace.findAll({where: {Uzivatel: req.params.ID}})
        .then(data => {
            if(!data) {
                return res.status(204).send({message: "Uživatel nevytvořil žádné příspěvky."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování příspěvků."});
        });
}

/**
 * Request GET, route "uzivatel/:ID/prispevky". Gets all current user's contributions.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.uzivatelAktualniPrispevky = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    models.Prezentace.findAll({where: {Uzivatel: tokenDecode.ID}})
        .then(data => {
            if(!data) {
                return res.status(204).send({message: "Uživatel nevytvořil žádné příspěvky."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování příspěvků."});
        });
}

/**
 * Request GET, route "konference/:Nazev/prispevky". Gets all contributions under a conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.konferencePrispevky = async (req, res) => {
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    models.Prezentace.findAll({where: {Konference: req.params.Nazev}, order: [['Zacatek_cas', 'ASC']]})
        .then(data => {
            if(!data) {
                return res.status(204).send({message: "Konference neobsahuje žádné příspěvky."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování příspěvků."});
        });
}

/**
 * Request GET, route "konference/:Nazev/prispevky/schvalene". Gets all approved contributions under a conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.konferencePrispevkyS = async (req, res) => {
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    models.Prezentace.findAll({where: {Konference: req.params.Nazev, jeSchvalena: true}, order: [['Zacatek_cas', 'ASC']]})
        .then(data => {
            if(!data) {
                return res.status(204).send({message: "Konference neobsahuje žádné schválené příspěvky."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování příspěvků."});
        });
}

/**
 * Request GET, route "konference/:Nazev/prispevky/neschvalene". Gets all unapproved contributions under a conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.konferencePrispevkyN = async (req, res) => {
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    models.Prezentace.findAll({where: {Konference: req.params.Nazev, jeSchvalena: false}})
        .then(data => {
            if(!data) {
                return res.status(204).send({message: "Konference neobsahuje žádné neschválené příspěvky."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování příspěvků."});
        });
}

/**
 * Request GET, route "konference/:Nazev/:Mistnost/prispevky". Gets all contributions under a room.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.mistnostPrispevky = async (req, res) => {
    let mistnost = await models.Mistnost.findByPk(req.params.Mistnost);
    if (!mistnost) {
        return res.status(404).send({message: `Místnost s kódem ${req.params.Mistnost} neexistuje.`});
    }
    models.Prezentace.findAll({where: {Mistnost: req.params.Mistnost}, order: [['Zacatek_cas', 'ASC']]})
        .then(data => {
            if(!data) {
                return res.status(204).send({message: "V místnosti se nekonají žádné příspěvky."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování příspěvků."});
        });
}

/**
 * Request PUT, route "konference/:Nazev/prispevky/:ID/schvalit". Approves a contribution.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.schvalit = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    let tokenDecode = tokenConfig.getData(req, res);
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    if (konference.Poradatel != tokenDecode.ID) {
        return res.status(403).send({message: `Pouze pořadatel konference s názvem ${req.params.Nazev} je oprávněn dělat změny.`});
    }
    
    if (req.body.jeSchvalena == "true") {
        if (!req.body.Mistnost || !req.body.Zacatek_cas || !req.body.Konec_cas) {
            return res.status(400).send({message: "Prosím vyplňte pole místnost, čas (začátek) a čas (konec)."});
        }
    } else {
        if (!req.body.poznamkyPoradatele || req.body.Mistnost || req.body.Zacatek_cas || req.body.Konec_cas) {
            return res.status(400).send({message: "V případě neschváleného příspěvku je třeba vyplnit pole poznámka pořadatele. Ostatní pole musí zůstat nevyplněna."});
        }
    }

    if (req.body.Zacatek_cas && req.body.Konec_cas) {
        if (req.body.Zacatek_cas >= req.body.Konec_cas) {
            return res.status(422).send({message: "Příspěvek začíná ve stejnou dobu nebo později než končí."});
        }
    }

    if (req.body.jeSchvalena == "true") {
        let kolize = await sequelize.query("SELECT * FROM `Prezentace` WHERE (((Zacatek_cas < :Z AND Konec_cas > :Z) OR (Zacatek_cas < :K AND Konec_cas > :K) OR (Zacatek_cas >= :Z AND Konec_cas <= :K)) AND Mistnost = :M)", { replacements: { Z: req.body.Zacatek_cas, K: req.body.Konec_cas, M: req.body.Mistnost }, type: sequelize.QueryTypes.SELECT})
        if (kolize[0]) {
            return res.status(409).send({message: `Časová kolize s příspěvkem ${kolize[0].Nazev} (ID ${kolize[0].ID}), který v místnosti ${kolize[0].Mistnost} začíná v čase ${kolize[0].Zacatek_cas} a končí v čase ${kolize[0].Konec_cas}.`});
        }

        let konfCas = await models.Konference.findByPk(req.params.Nazev);
        if (req.body.Zacatek_cas < konfCas.Zacatek_cas || req.body.Zacatek_cas > konfCas.Konec_cas ||
            req.body.Konec_cas < konfCas.Zacatek_cas || req.body.Konec_cas > konfCas.Konec_cas) {
                return res.status(409).send({message: `Nastavený čas neodpovídá času konání konference (${konfCas.Zacatek_cas} - ${konfCas.Konec_cas}).`});
            }
    }
        
    models.Prezentace.update(req.body, {where: {ID: req.params.ID}})
        .then(data => {
            models.Prezentace.findByPk(req.params.ID)
                .then(data => {
                    res.send(data);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při upravování příspěvku."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při upravování konference."});
        });
}
