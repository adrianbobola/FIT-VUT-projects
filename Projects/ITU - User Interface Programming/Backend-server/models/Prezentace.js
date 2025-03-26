/**
 * @file Generated models needed for the database actions - table Prezentace.
 */

const Sequelize = require('sequelize');
module.exports = function(sequelize, DataTypes) {
  return sequelize.define('Prezentace', {
    ID: {
      autoIncrement: true,
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true
    },
    Nazev: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Konference: {
      type: DataTypes.STRING(255),
      allowNull: true,
      references: {
        model: 'Konference',
        key: 'Nazev'
      }
    },
    Uzivatel: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'Uzivatel',
        key: 'ID'
      }
    },
    Popis: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    Tagy: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Grafika: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Soubor: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    Mistnost: {
      type: DataTypes.STRING(20),
      allowNull: true,
      references: {
        model: 'Mistnost',
        key: 'Kod'
      }
    },
    jeSchvalena: {
      type: DataTypes.BOOLEAN,
      allowNull: true
    },
    Datum: {
      type: DataTypes.DATEONLY,
      allowNull: true
    },
    Zacatek_cas: {
      type: DataTypes.TIME,
      allowNull: true
    },
    Konec_cas: {
      type: DataTypes.TIME,
      allowNull: true
    },
    poznamkyPoradatele: {
      type: DataTypes.TEXT,
      allowNull: true
    }
  }, {
    sequelize,
    tableName: 'Prezentace',
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
        name: "FK_Konference_P",
        using: "BTREE",
        fields: [
          { name: "Konference" },
        ]
      },
      {
        name: "FK_Mistnost",
        using: "BTREE",
        fields: [
          { name: "Mistnost" },
        ]
      },
      {
        name: "FK_Prezentuje",
        using: "BTREE",
        fields: [
          { name: "Uzivatel" },
        ]
      },
    ]
  });
};
