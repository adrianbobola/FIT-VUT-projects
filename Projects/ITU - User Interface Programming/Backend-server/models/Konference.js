/**
 * @file Generated models needed for the database actions - table Konference.
 */

const Sequelize = require('sequelize');
module.exports = function(sequelize, DataTypes) {
  return sequelize.define('Konference', {
    Nazev: {
      type: DataTypes.STRING(255),
      allowNull: false,
      primaryKey: true
    },
    Popis: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    Obor: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Zeme: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Mesto: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Misto: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Zacatek_datum: {
      type: DataTypes.DATEONLY,
      allowNull: false
    },
    Konec_datum: {
      type: DataTypes.DATEONLY,
      allowNull: false
    },
    Zacatek_cas: {
      type: DataTypes.TIME,
      allowNull: false
    },
    Konec_cas: {
      type: DataTypes.TIME,
      allowNull: false
    },
    Poplatek: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    Cena_vstup: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    Kapacita: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    ZbyvajiciKapacita: {
      type: DataTypes.INTEGER,
      allowNull: true
    },
    Poradatel: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'Uzivatel',
        key: 'ID'
      }
    },
    Doplnujici_udaje: {
      type: DataTypes.TEXT,
      allowNull: true
    }
  }, {
    sequelize,
    tableName: 'Konference',
    timestamps: false,
    indexes: [
      {
        name: "PRIMARY",
        unique: true,
        using: "BTREE",
        fields: [
          { name: "Nazev" },
        ]
      },
      {
        name: "FK_Poradatel",
        using: "BTREE",
        fields: [
          { name: "Poradatel" },
        ]
      },
    ]
  });
};
