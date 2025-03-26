/**
 * @author Tereza Burianova (xburia28)
 * @file Authorization check used in routers.
 */

const passport = require('passport');

exports.isLoggedIn = passport.authenticate('jwt',  { session: false });
