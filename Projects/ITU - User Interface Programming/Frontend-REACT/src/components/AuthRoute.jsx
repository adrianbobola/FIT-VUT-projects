/**
 * ITU - projekt, VUT FIT Brno
 * @author Tereza Burianová, xburia28
 * @file AuthRoute.jsx
 */
import React from "react";
import {Navigate} from "react-router-dom";
import Auth from "./Authentificate"

/**
 * Returns Html to display if user is authorized(logged in)
 * otherwise it redirects user to login page
 * @param {*} param0 Html to display
 */
function ProtectedRoute({ children }) {
    const isAuth = Auth.authentificated;
    return isAuth ? children : <Navigate to="../signIn" />;
}

function UnprotectedRoute({ children }) {
    const isAuth = Auth.authentificated;
    return !isAuth ? children : null;
}

export default ProtectedRoute;
export {UnprotectedRoute}