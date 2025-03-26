var DataTypes = require("sequelize").DataTypes;
var _Konference = require("./Konference");
var _Mistnost = require("./Mistnost");
var _Prezentace = require("./Prezentace");
var _R_Oblibene_Konference = require("./R_Oblibene_Konference");
var _Rezervace = require("./Rezervace");
var _Uzivatel = require("./Uzivatel");

function initModels(sequelize) {
  var Konference = _Konference(sequelize, DataTypes);
  var Mistnost = _Mistnost(sequelize, DataTypes);
  var Prezentace = _Prezentace(sequelize, DataTypes);
  var R_Oblibene_Konference = _R_Oblibene_Konference(sequelize, DataTypes);
  var Rezervace = _Rezervace(sequelize, DataTypes);
  var Uzivatel = _Uzivatel(sequelize, DataTypes);

  Konference.belongsToMany(Uzivatel, { as: 'ID_Uzivatels', through: R_Oblibene_Konference, foreignKey: "Nazev", otherKey: "ID" });
  Uzivatel.belongsToMany(Konference, { as: 'Nazev_Konferences', through: R_Oblibene_Konference, foreignKey: "ID", otherKey: "Nazev" });
  Mistnost.belongsTo(Konference, { as: "Konference_Konference", foreignKey: "Konference"});
  Konference.hasMany(Mistnost, { as: "Mistnosts", foreignKey: "Konference"});
  Prezentace.belongsTo(Konference, { as: "Konference_Konference", foreignKey: "Konference"});
  Konference.hasMany(Prezentace, { as: "Prezentaces", foreignKey: "Konference"});
  R_Oblibene_Konference.belongsTo(Konference, { as: "Nazev_Konference", foreignKey: "Nazev"});
  Konference.hasMany(R_Oblibene_Konference, { as: "R_Oblibene_Konferences", foreignKey: "Nazev"});
  Rezervace.belongsTo(Konference, { as: "Konference_Konference", foreignKey: "Konference"});
  Konference.hasMany(Rezervace, { as: "Rezervaces", foreignKey: "Konference"});
  Prezentace.belongsTo(Mistnost, { as: "Mistnost_Mistnost", foreignKey: "Mistnost"});
  Mistnost.hasMany(Prezentace, { as: "Prezentaces", foreignKey: "Mistnost"});
  Konference.belongsTo(Uzivatel, { as: "Poradatel_Uzivatel", foreignKey: "Poradatel"});
  Uzivatel.hasMany(Konference, { as: "Konferences", foreignKey: "Poradatel"});
  Prezentace.belongsTo(Uzivatel, { as: "Uzivatel_Uzivatel", foreignKey: "Uzivatel"});
  Uzivatel.hasMany(Prezentace, { as: "Prezentaces", foreignKey: "Uzivatel"});
  R_Oblibene_Konference.belongsTo(Uzivatel, { as: "ID_Uzivatel", foreignKey: "ID"});
  Uzivatel.hasMany(R_Oblibene_Konference, { as: "R_Oblibene_Konferences", foreignKey: "ID"});
  Rezervace.belongsTo(Uzivatel, { as: "Uzivatel_Uzivatel", foreignKey: "Uzivatel"});
  Uzivatel.hasMany(Rezervace, { as: "Rezervaces", foreignKey: "Uzivatel"});

  return {
    Konference,
    Mistnost,
    Prezentace,
    R_Oblibene_Konference,
    Rezervace,
    Uzivatel,
  };
}
module.exports = initModels;
module.exports.initModels = initModels;
module.exports.default = initModels;
