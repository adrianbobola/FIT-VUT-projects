/**
 * @author Adrian Bobola (xbobol00)
 * @file Controller for the actions related to reservations.
 */

const sequelize = require('../../config/database.js');
const initModels = require("../../models/init-models");
const models = initModels(sequelize);
const tokenConfig = require('../../config/token');
const bcrypt = require('bcrypt-nodejs');
const konferenceC = require('./konference');

/**
 * Request POST, route "konference/:Nazev/novaRezervace". Creates a contribution under the current user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.vytvoritAktualni = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    if (!req.body.Pocet_vstupenek) {
        return res.status(400).send({message: "Prosím vyplňte pole počet vstupenek."});
    }
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    if (konference.ZbyvajiciKapacita < req.body.Pocet_vstupenek) {
        return res.status(409).send({message: `Nedostatek kapacity na konferenci. Volná kapacita: ${konference.ZbyvajiciKapacita}`});
    }

    let rezervace = req.body;
    let tokenDecode = tokenConfig.getData(req, res);
    rezervace.Uzivatel = tokenDecode.ID;
    rezervace.Konference = req.params.Nazev;
    rezervace.Jmeno = undefined;
    rezervace.Prijmeni = undefined;
    rezervace.Email = undefined;
    rezervace.Stav = "vytvoreno";
    rezervace.Celkova_cena = konference.Cena_vstup * rezervace.Pocet_vstupenek;

    models.Rezervace.create(rezervace)
        .then(async data => {
            let zbyva = konference.ZbyvajiciKapacita - rezervace.Pocet_vstupenek;
            await konference.update({ ZbyvajiciKapacita: zbyva});
            models.Rezervace.findByPk(data.ID)
                .then(data2 => {
                    res.send(data2);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při vytváření rezervace."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při vytváření rezervace."});
        });
}

/**
 * Request POST, route "konference/:Nazev/novaRezervace/nereg". Creates a reservation under an unregistered user without registration.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.vytvoritBezReg = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    if (!req.body.Pocet_vstupenek || !req.body.Jmeno || !req.body.Prijmeni || !req.body.Email) {
        return res.status(400).send({message: "Prosím vyplňte pole počet vstupenek, jméno, příjmení a email."});
    }
    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    if (konference.ZbyvajiciKapacita < req.body.Pocet_vstupenek) {
        return res.status(409).send({message: `Nedostatek kapacity na konferenci. Volná kapacita: ${konference.ZbyvajiciKapacita}`});
    }

    let rezervace = req.body;
    rezervace.Uzivatel = undefined;
    rezervace.Konference = req.params.Nazev;
    rezervace.Stav = "vytvoreno";
    rezervace.Celkova_cena = konference.Cena_vstup * rezervace.Pocet_vstupenek;

    models.Rezervace.create(rezervace)
        .then(async data => {
            let zbyva = konference.ZbyvajiciKapacita - rezervace.Pocet_vstupenek;
            await konference.update({ ZbyvajiciKapacita: zbyva});
            models.Rezervace.findByPk(data.ID)
                .then(data2 => {
                    res.send(data2);
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při vytváření rezervace."});
                });
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při vytváření rezervace."});
        });
}

/**
 * Request POST, route "konference/:Nazev/novaRezervace/reg". Creates a reservation under an unregistered user with registration.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.vytvoritSReg = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }
    if (!req.body.Pocet_vstupenek) {
        return res.status(400).send({message: "Prosím vyplňte pole počet vstupenek."});
    }

    let konference = await models.Konference.findByPk(req.params.Nazev);
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    

    if (!req.body.Jmeno || !req.body.Prijmeni || !req.body.Email || !req.body.Heslo) {
        return res.status(400).send({message: "Prosím vyplňte pole jméno, příjmení, email a heslo."});
    } else {
        const uzivatelCheck = await models.Uzivatel.findOne({where: {Email: req.body.Email}});
        if (uzivatelCheck) {
            return res.status(422).send({message: "Uživatel s tímto emailem již existuje."});
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
                        let rezervace = req.body;
                        rezervace.Celkova_cena = konference.Cena_vstup * rezervace.Pocet_vstupenek;
                        rezervace.Uzivatel = data.ID;
                        rezervace.Konference = req.params.Nazev;
                        rezervace.Jmeno = undefined;
                        rezervace.Prijmeni = undefined;
                        rezervace.Email = undefined;
                        rezervace.Stav = "vytvoreno";
                        
                        if (konference.ZbyvajiciKapacita < req.body.Pocet_vstupenek) {
                            return res.status(409).send({message: `Nedostatek kapacity na konferenci. Volná kapacita: ${konference.ZbyvajiciKapacita}`});
                        }

                        models.Rezervace.create(rezervace)
                            .then(async data => {
                                let zbyva = konference.ZbyvajiciKapacita - rezervace.Pocet_vstupenek;
                                await konference.update({ ZbyvajiciKapacita: zbyva});
                                models.Rezervace.findByPk(data.ID)
                                    .then(data2 => {
                                        res.send(data2);
                                    })
                                    .catch(err => {
                                        return res.status(500).send({message: err.message || "Chyba při vytváření rezervace."});
                                    });
                            })
                            .catch(err => {
                                return res.status(500).send({message: err.message || "Chyba při vytváření rezervace."});
                            });
                    })
                    .catch(err => {
                        return res.status(500).send({message: err.message || "Chyba při vytváření uživatele. " + err});
                    });
            });
        });
    }

}

/**
 * Request POST, route "konference/:Nazev/rezervace/:ID/odstranit". Removes a reservation.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.odstranit = async (req, res) => {
    if (!req.body) {
        return res.status(400).send({message: "Empty body content."});
    }

    let tokenDecode = tokenConfig.getData(req, res);
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    let rezervace = await models.Rezervace.findByPk(req.params.ID);
    if (!rezervace) {
        return res.status(404).send({message: `Rezervace s ID ${req.params.ID} neexistuje.`});
    }
    if (konference.Poradatel != tokenDecode.ID && rezervace.Uzivatel != tokenDecode.ID) {
        return res.status(403).send({message: `Pouze pořadatel konference nebo uživatel přiřazený k rezervaci je oprávněn dělat změny.`});
    }
    var uvolnenaKapacita = rezervace.Pocet_vstupenek;

    models.Rezervace.destroy({where: {ID: req.params.ID}})
        .then(data => {
            models.Konference.increment('ZbyvajiciKapacita', { by: uvolnenaKapacita, where: { Nazev: req.params.Nazev } })
                .then(data => {
                    return res.send({message: `Rezervace s ID ${req.params.ID} byla odstraněna.`});
                })
                .catch(err => {
                    return res.status(500).send({message: err.message || "Chyba při mazání rezervace."});
                })
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při mazání rezervace."});
        });
}

/**
 * Request PUT, route "konference/:Nazev/rezervace/:ID/potvrdit". Approves a reservation.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.potvrdit = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    if (konference.Poradatel != tokenDecode.ID) {
        return res.status(403).send({message: `Pouze pořadatel konference je oprávněn potvrdit rezervaci.`});
    }

    models.Rezervace.update({Stav: 'zaplaceno'}, {where: {ID: req.params.ID}})
        .then(data => {
            res.send({message: `Rezervace s ID ${req.params.ID} byla potvrzena.`})
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při potvrzování rezervace."});
        })
}

/**
 * Request GET, route "konference/:Nazev/rezervace/:ID". Gets a reservation (with information about conference).
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazit = async (req, res) => {
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    let rezervace = await models.Rezervace.findByPk(req.params.ID);
    if (!rezervace) {
        return res.status(404).send({message: `Rezervace s ID ${req.params.ID} neexistuje.`});
    }
    res.send(rezervace);
}

/**
 * Request GET, route "konference/rezervace/:ID". Gets a reservation (by reservation ID only).
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitID = async (req, res) => {
    let rezervace = await models.Rezervace.findByPk(req.params.ID);
    if (!rezervace) {
        return res.status(404).send({message: `Rezervace s ID ${req.params.ID} neexistuje.`});
    }
    res.send(rezervace);
}

/**
 * Request GET, route "konference/:Nazev/rezervace/". Gets all reservations under a conference.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitKonference = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: `Konference s názvem ${req.params.Nazev} neexistuje.`});
    }
    if (konference.Poradatel != tokenDecode.ID) {
        return res.status(403).send({message: `Pouze pořadatel konference je oprávněn potvrdit rezervaci.`});
    }
    models.Rezervace.findAll({where: {Konference: req.params.Nazev}})
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování rezervací."});
        })
}

/**
 * Request GET, route "uzivatel/rezervace". Gets all reservations under a user.
 * @param {application/json} req Request.
 * @param {application/json} res Response.
 * @returns Json with message and http code in the case of an error.
 */
exports.zobrazitUzivatel = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    models.Rezervace.findAll({where: {Uzivatel: tokenDecode.ID}})
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování rezervací."});
        })
}