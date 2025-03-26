/**
 * @author Tereza Burianova (xburia28)
 * @file Main server initialization.
 */

const express = require('express');
const passport = require('passport');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config()
const sequelize = require('./config/database.js');
const PORT = 8000;

const passportConfig = require("./config/passport");
const konferenceRouter = require("./routes/konference.router");
const uzivatelRouter = require("./routes/uzivatel.router");
const administraceRouter = require("./routes/administrace.router");

const init = async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection has been established successfully.');
    const app = express();
  
    app.use(cors());
    app.use(passport.initialize());
    passportConfig(passport);
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));
    app.use(express.json());
    app.use(express.static("express"));
  
    app.use("/konference", konferenceRouter);
    app.use("/uzivatel", uzivatelRouter);
    app.use("/admin", administraceRouter);
  
    app.listen(PORT, () => console.log(`Server is listening on port ${PORT}...`))

  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
}

init();
