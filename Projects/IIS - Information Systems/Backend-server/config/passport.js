/**
 * @author Tereza Burianova (xburia28)
 * @file Authentication check according to the bearer token.
 */

const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const sequelize = require('./database.js');
const initModels = require("../models/init-models");
const models = initModels(sequelize);

module.exports = passport => {
    let opts = {};
    opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
    opts.secretOrKey = process.env.SECRET || '';
    passport.use(new JwtStrategy(opts, async (payload, done) => {
        const user = await models.Uzivatel.findOne({where: {ID: payload.ID}});
        if (!user) return done(null, false);
        return done(null, user);
    }));
};
