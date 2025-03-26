/**
 * ITU - projekt, VUT FIT Brno
 * @author Adrián Bobola, xbobol00
 * @file Map.jsx
 */
import React from "react";
import { GoogleMap, useJsApiLoader, Marker } from '@react-google-maps/api';
import "./FooterMap.css";

/**
 * Google map
 * @returns Html
 */
function Map() {
  const { isLoaded } = useJsApiLoader({
    id: 'google-map-script',
    googleMapsApiKey: "AIzaSyDWOkScu-nAAxLh9CCzsRnX57pEKQx8yto"
  })

  const CENTER = {
    lat: 49.20333367689001, 
    lng: 16.61294652303453
  };

  const D105 = {
    lat: 49.22621473426841,
    lng: 16.59686130849238
  };

  const FEKT = {
    lat: 49.22617310055418,
    lng: 16.576089288011943
  };

  const NADRAZI = {
    lat: 49.19137973588247,
    lng: 16.61231258365838
  }

  return (
    <div className="map">
      {
        isLoaded ? (
          <GoogleMap
            mapContainerStyle={{ width: "100%", height: "100%" }}
            center={CENTER}
            zoom={13}
          >
            <Marker
              position={D105}
              options={{
                label: {
                  text: "FIT VUT - D105",
                  className: "mapMargin"
                }
              }}
            />

            <Marker
              position={FEKT}
              options={{
                label: {
                  text: "FEKT VUT",
                  className: "mapMargin"
                }
              }}
            />

            <Marker
              position={NADRAZI}
              options={{
                label: {
                  text: "Hlavní nádraží",
                  className: "mapMargin"
                }
              }}
            />
          </GoogleMap>
        )
          :
          <div>
            <h4>Načitávam mapu...</h4>
          </div>
      }
    </div>
  );
};

export default Map;