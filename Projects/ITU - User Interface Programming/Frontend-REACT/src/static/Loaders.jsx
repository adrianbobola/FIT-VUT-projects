/**
 * ITU - projekt, VUT FIT Brno
 * @author Timotej Ponek, xponek00
 * @file Loaders.jsx
 */

import { useState, useEffect } from 'react';

/**
 * Promise get method
 * @param {*} url server url route
 * @param {*} token authorization token
 * @returns {*} { data, pending, error }
 */
const useGet = (url, token) => {
    const [data, setData] = useState(null);
    const [pending, setPending] = useState(true);
    const [error, setError] = useState(null);
  
    useEffect(() => {
      const abortCont = new AbortController();
  
      fetch(url, { 
          signal: abortCont.signal,
          method: 'GET',
          headers: {
              'Authorization' : window.localStorage.getItem("token")
            }
        })
      .then(res => {
          if (!res.ok) { // error coming back from server
              throw Error('Error: '+res.status+' could not fetch the data for that resource');
          } 
          return res.json();
        })
      .then(data => {
          setPending(false);
          setData(data);
          setError(null);
        })
      .catch(err => {
          if (err.name === 'AbortError') {
              console.log('fetch aborted')
          } else {
              // auto catches network / connection error
              setPending(false);
              setError(err.message);
          }
        })
  
      // abort the fetch
      return () => abortCont.abort();
    }, [url])
  
    return { data, pending, error };
}

/**
 * Promise post method
 * @param {*} url server url route
 * @param {*} token authorization token
 * @param {*} dataToPost should be stringified json 
 * @returns {*} data, pending, error
 */
const usePost = (url, token, dataToPost) => {
    const [data, setData] = useState(null);
    const [pending, setPending] = useState(true);
    const [error, setError] = useState(null);
  
    useEffect(() => {
      const abortCont = new AbortController();
  
      fetch(url, { 
          signal: abortCont.signal,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization' : window.localStorage.getItem("token")
          },
          body: dataToPost
        })
      .then(res => {
          if (!res.ok) { // error coming back from server
              setError('could not fetch the data for that resource')
          } 
          return res.json();
        })
      .then(data => {
          setPending(false);
          setData(data);
          if(error){
            alert(data)
          }
        })
      .catch(err => {
          if (err.name === 'AbortError') {
              console.log('fetch aborted')
          } else {
              // auto catches network / connection error
              setPending(false);
              setError(err.message);
          }
        })
  
      // abort the fetch
      return () => abortCont.abort();
    }, [url])
  
    return { data, pending, error };
}


/**
 * 
 * @param {*} url server url route
 * @param {*} token authorization token
 * @param {*} dataToPost should be stringified json 
 * @returns {*} data, pending, error
 */
async function Get (url, token) {

  let dataToReturn = null;
  let pending = true;
  let error = null;

  const abortCont = new AbortController();

  return(
    fetch(url, { 
        signal: abortCont.signal,
        method: 'GET',
        headers: {
          'Authorization' : window.localStorage.getItem("token")
        },
      })
      .then(res => {
        if (!res.ok) {
            error = 'could not fetch the data for that resource'
        } 
        return res.json();
      })
    .then(data => {
        pending = false;
        dataToReturn = data;
        if(error){
          alert(data.message)
        }
        return { dataToReturn, pending, error };
      })
    .catch(err => {
        if (err.name === 'AbortError') {
            console.log('post aborted')
            return { dataToReturn, pending, error };
        } else {
            // auto catches network / connection error
            pending = false;
            error = err.message;
            return { dataToReturn, pending, error };
        }
      })
  )
}

/**
 * 
 * @param {*} url server url route
 * @param {*} token authorization token
 * @param {*} dataToPost should be stringified json 
 * @returns {*} data, pending, error
 */
async function Post (url, token, dataToPost) {

  let dataToReturn = null;
  let pending = true;
  let error = null;

  const abortCont = new AbortController();

  return(
    fetch(url, { 
        signal: abortCont.signal,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization' : window.localStorage.getItem("token")
        },
        body: dataToPost
      })
      .then(res => {
        if (!res.ok) {
            error = 'could not fetch the data for that resource'
        } 
        return res.json();
      })
    .then(data => {
        pending = false;
        dataToReturn = data;
        if(error){
          alert(data.message)
        }
        return { dataToReturn, pending, error };
      })
    .catch(err => {
        if (err.name === 'AbortError') {
            console.log('post aborted')
            return { dataToReturn, pending, error };
        } else {
            // auto catches network / connection error
            pending = false;
            error = err.message;
            return { dataToReturn, pending, error };
        }
      })
  )
}

/**
 * 
 * @param {*} url server url route
 * @param {*} token authorization token
 * @param {*} dataToPost should be stringified json 
 * @returns {*} data, pending, error
 */
 async function Put (url, token, dataToPost) {

  let dataToReturn = null;
  let pending = true;
  let error = null;

  const abortCont = new AbortController();

  return(
    fetch(url, { 
        signal: abortCont.signal,
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization' : window.localStorage.getItem("token")
        },
        body: dataToPost
      })
    .then(res => {
        if (!res.ok) {
            error = 'could not fetch the data for that resource'
        } 
        return res.json();
      })
    .then(data => {
        pending = false;
        dataToReturn = data;
        if(error){
          alert(data.message)
        }
        return { dataToReturn, pending, error };
      })
    .catch(err => {
        if (err.name === 'AbortError') {
            console.log('post aborted')
            return { dataToReturn, pending, error };
        } else {
            // auto catches network / connection error
            pending = false;
            error = err.message;
            return { dataToReturn, pending, error };
        }
      })
  )
}


export {useGet, usePost, Get, Post, Put};