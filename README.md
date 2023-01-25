# fiat_vehicle

This PHP script should make it possible to receive status information from your FIAT car.

## Sources

Following sources were used to generate this PHP script:
- https://community.openhab.org/t/fiat-uconnect-getting-bev-information-into-openhab/141508
- https://docs.guzzlephp.org/en/stable/psr7.html
- https://github.com/wubbl0rz/FiatChamp/blob/master/FiatChampAddon/FiatClient/FiatClient.cs
- https://github.com/evcc-io/evcc/tree/master/vehicle/fiat
- https://stackoverflow.com/questions/4356289/php-random-string-generator

Thanks to all, which helped with some puzzle parts. It was not so easy to combine a C# and a Go implementation to a PHP one. I tried to use standard functions (CURL) or standard bundles like the AWS one as far as possible to make the script reuseable also in other coding languages.

## Status and further steps:

- So far it is tested until the getVehicles-Request.
- getVehicleStatus and getVehicleLocation will be tested as soon we received our Fiat car. Feel free to test in your setup and let me know if it works or not.
- Command requests to come later (as soon we have a car to test with)
- As I'm using #OpenHAB as a smart home plattform I would highly appreciate if this PHP script could be a good starting point to develop a FIAT binding.
- Unfortunately I'm not familiar with binding development for OpenHAB, but maybe someone else could help out to do the programming part. I would support on the testing part.

## How to use?

An example for how to call the is shown in the example.php

## How to contribute?

Please send information provided by exportInformation() function, so that I could do some tests with real vehicle data (before I have a Fiat car available). Feel free to XXX-out sensible information, but please don't delete complete information blocks. 