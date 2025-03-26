/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file DeleteUser.jsx
 */
import React, { useState } from 'react'

/**
 * Delete user functionality
 * @param Delete delete function
 * @returns 
 */
function DeleteUser({Delete}) {

    const submitHandler = e => {
        e.preventDefault();

        Delete();
    }

    return (
        <div>
            <button class="w-100 btn btn-lg btn-outline-danger"
            onClick={(event) => {
                const confirmBox = window.confirm(
                    'Jste si jist že chcete odstranit účet?'
                )
                if (confirmBox === true) {
                    submitHandler(event);
                }
              }}
            >Zmazat účet</button>
        </div>
    )
}

export default DeleteUser
