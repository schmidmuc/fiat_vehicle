<?php

// Include the api file (take care of the correct path)
include ( api.php );

// Create a new instance with your FIAT user account credentials
$fiat = new apiFiat( FIAT_USER, FIAT_PASSWORD );

// Get all information from all vehicles linked to the user account
$fiat->apiRequestAll ();

// Finally print all log messages
echo $fiat->getLog ();

// Export the vehicle data information for further development/testing
echo $fiat->exportInformation();