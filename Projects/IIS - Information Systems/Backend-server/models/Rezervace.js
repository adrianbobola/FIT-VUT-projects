/**
 * @file Generated models needed for the database actions - table Rezervace.
 */

const Sequelize = require('sequelize');
module.exports = function(sequelize, DataTypes) {
  return sequelize.define('Rezervace', {
    ID: {
      autoIncrement: true,
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true
    },
    Konference: {
      type: DataTypes.STRING(255),
      allowNull: false,
      references: {
        model: 'Konference',
        key: 'Nazev'
      }
    },
    Uzivatel: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'Uzivatel',
        key: 'ID'
      }
    },
    Jmeno: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Prijmeni: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Email: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Datum_vytvoreni: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: Sequelize.Sequelize.literal('CURRENT_TIMESTAMP')
    },
    Pocet_vstupenek: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    Celkova_cena: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    Stav: {
      type: DataTypes.STRING(20),
      allowNull: true
    }
  }, {
    sequelize,
    tableName: 'Rezervace',
    timestamps: false,
    indexes: [
      {
        name: "PRIMARY",
        unique: true,
        using: "BTREE",
        fields: [
          { name: "ID" },
        ]
      },
      {
        name: "FK_Konference",
        using: "BTREE",
        fields: [
          { name: "Konference" },
        ]
      },
      {
        name: "FK_Uzivatel",
        using: "BTREE",
        fields: [
          { name: "Uzivatel" },
        ]
      },
    ]
  });
};
