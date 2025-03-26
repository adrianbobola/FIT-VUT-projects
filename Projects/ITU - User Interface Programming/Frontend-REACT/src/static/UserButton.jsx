/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file UserButton.jsx
 */

import React from 'react'
import { NavLink } from 'react-router-dom';

/**
 * Button that redirects user to user profile
 * @param {*} id id of user 
 * @returns 
 */
export default function UserButton({id}) {

    const navlink = "/uzivatel/"+id;

    return (
        <div>
            <NavLink className="nav-link" to={navlink}>
                 Uživatel s id: {id}
            </NavLink>
        </div>
    )
}
