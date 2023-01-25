<?php

// Include the api file (take care of the correct path)
include ( api.php );

// Create a new instance with your FIAT user account credentials
$fiat = new apiFiat( FIAT_USER, FIAT_PASSWORD );

// Get all vehicles (VIN) linked to the user account
$vinArray = $fiat->getVehicles ();

// Check if there are vehicle VINs in the result array
if ( is_array($vinArray) ) {

	// For each vehicle VIN ...	
	foreach ($vinArray as $vin) {
		
		// ... get the vehicle status and ...
		$fiat->getVehicleStatus ( $vin );

		// ... get the locaction of the vehicle
		$fiat->getVehicleLocation ( $vin );

  	}
}

// Finally print all log messages
echo $fiat->getLog ();