/**
 * @file Generated models needed for the database actions - table Mistnost.
 */

const Sequelize = require('sequelize');
module.exports = function(sequelize, DataTypes) {
  return sequelize.define('Mistnost', {
    Kod: {
      type: DataTypes.STRING(20),
      allowNull: false,
      primaryKey: true
    },
    Popis: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    Vybaveni: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    Konference: {
      type: DataTypes.STRING(255),
      allowNull: true,
      references: {
        model: 'Konference',
        key: 'Nazev'
      }
    }
  }, {
    sequelize,
    tableName: 'Mistnost',
    timestamps: false,
    indexes: [
      {
        name: "PRIMARY",
        unique: true,
        using: "BTREE",
        fields: [
          { name: "Kod" },
        ]
      },
      {
        name: "FK_Konference_M",
        using: "BTREE",
        fields: [
          { name: "Konference" },
        ]
      },
    ]
  });
};
