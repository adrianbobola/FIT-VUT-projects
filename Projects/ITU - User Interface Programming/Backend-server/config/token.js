/**
 * @author Tereza Burianova (xburia28)
 * @file Gets data about the user from the bearer token.
 */

const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');

/**
 * Gets rid of additional information provided by the frontend.
 * @param {string} headerToken Bearer token sent by the frontend in a special format.
 * @returns Token without other information provided by the frontend.
 */
exports.getToken = (headerToken) => {
    if (!headerToken) {
        return null;
    }
    const splitToken = headerToken.split(' ');
    if (splitToken.length < 2) {
        return null;
    }
    return splitToken[1];
};

/**
 * Gets data from the bearer token.
 * @param {application/json} req Request.
 * @returns Data decoded fron the bearer token.
 */
exports.getData = (req) => {
    try {
        let tokenDecode = jwt.verify(this.getToken(req.headers.authorization), process.env.SECRET);
        return tokenDecode;
    } catch(err) {
        return err;
    }
}
