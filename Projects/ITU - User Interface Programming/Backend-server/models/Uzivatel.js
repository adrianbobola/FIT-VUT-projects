/**
 * @file Generated models needed for the database actions - table Uzivatel.
 */

const Sequelize = require('sequelize');
module.exports = function(sequelize, DataTypes) {
  return sequelize.define('Uzivatel', {
    ID: {
      autoIncrement: true,
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true
    },
    Jmeno: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Prijmeni: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Heslo: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Titul: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Role: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    Organizace: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Obor: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Zeme: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Datum_narozeni: {
      type: DataTypes.DATEONLY,
      allowNull: true
    },
    Email: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    TelCislo: {
      type: DataTypes.STRING(255),
      allowNull: true
    }
  }, {
    sequelize,
    tableName: 'Uzivatel',
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
    ]
  });
};
