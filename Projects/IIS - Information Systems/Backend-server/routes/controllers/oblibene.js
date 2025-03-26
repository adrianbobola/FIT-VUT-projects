/**
 * @author Tereza Burianova (xburia28)
 * @file Controller for the actions related to favourite conferences.
 */

 const sequelize = require('../../config/database.js');
 const initModels = require("../../models/init-models");
 const models = initModels(sequelize);
 const tokenConfig = require('../../config/token');
const { param } = require('../uzivatel.router.js');


 exports.zobrazitOblibene = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let oblibeneK = [];
    models.R_Oblibene_Konference.findAll({
        attributes: ['Nazev'],
        where: {ID: tokenDecode.ID}
    })
    .then(data => {
        oblibeneK = data.map(konf => konf.Nazev);

        models.Konference.findAll({
            where: {Nazev: oblibeneK}
        })
        .then(data => {
            if(!data) {
                return res.status(404).send({message: "Uživatel nemá žádné oblíbené konference."});
            }
            res.send(data);
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při zobrazování oblíbených konferencí."});
        });
    })
    .catch(err => {
        return res.status(500).send({message: err.message || "Chyba při zobrazování oblíbených konferencí."});
    });

}

exports.pridatOblibene = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: "Konference neexistuje."});;
    }
    let zaznam = {Nazev: req.params.Nazev, ID: tokenDecode.ID};
    models.R_Oblibene_Konference.create(zaznam)
    .then(data => {
        res.send(data);
    })
    .catch(err => {
        return res.status(500).send({message: err.message || "Chyba při označování konference za oblíbenou."});
    });
}

exports.odebratOblibene = async (req, res) => {
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: "Konference neexistuje."});;
    }
    let tokenDecode = tokenConfig.getData(req, res);
    models.R_Oblibene_Konference.destroy({where: {ID: tokenDecode.ID, Nazev:req.params.Nazev}})
    .then(data => {
        res.send("Oblíbená konference byla odstraněna.");
    })
    .catch(err => {
        return res.status(500).send({message: err.message || "Chyba při odebírání oblíbené konference."});
    });
}

exports.jeOblibena = async (req, res) => {
    let tokenDecode = tokenConfig.getData(req, res);
    let konference = await models.Konference.findOne({where: {Nazev: req.params.Nazev}});
    if (!konference) {
        return res.status(404).send({message: "Konference neexistuje."});;
    }
    models.R_Oblibene_Konference.findOne({where: {Nazev: req.params.Nazev, ID:tokenDecode.ID}})
        .then(data => {
            if (!data) {
                res.send({oblibena: false});
            } else {
                res.send({oblibena: true});
            }
        })
        .catch(err => {
            return res.status(500).send({message: err.message || "Chyba při ověřování oblíbených konferencí."});
        });
}
