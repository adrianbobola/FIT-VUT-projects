const Sequelize = require('sequelize');
module.exports = function(sequelize, DataTypes) {
  return sequelize.define('R_Oblibene_Konference', {
    ID: {
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true,
      references: {
        model: 'Uzivatel',
        key: 'ID'
      }
    },
    Nazev: {
      type: DataTypes.STRING(255),
      allowNull: false,
      primaryKey: true,
      references: {
        model: 'Konference',
        key: 'Nazev'
      }
    }
  }, {
    sequelize,
    tableName: 'R_Oblibene_Konference',
    timestamps: false,
    indexes: [
      {
        name: "PRIMARY",
        unique: true,
        using: "BTREE",
        fields: [
          { name: "ID" },
          { name: "Nazev" },
        ]
      },
      {
        name: "Nazev_FK",
        using: "BTREE",
        fields: [
          { name: "Nazev" },
        ]
      },
    ]
  });
};
