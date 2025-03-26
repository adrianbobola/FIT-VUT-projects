/**
 * @author Tereza Burianova (xburia28)
 * @file Database configuration.
 */

const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('ituproject', process.env.DB_NICK, process.env.DB_PWD, {
  host: 'localhost',
  dialect: 'mysql'
});

module.exports = sequelize;
