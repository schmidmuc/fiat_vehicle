# fiat_vehicle

Following sources were used to generate this PHP script:
- https://community.openhab.org/t/fiat-uconnect-getting-bev-information-into-openhab/141508
- https://docs.guzzlephp.org/en/stable/psr7.html
- https://github.com/wubbl0rz/FiatChamp/blob/master/FiatChampAddon/FiatClient/FiatClient.cs
- https://github.com/evcc-io/evcc/tree/master/vehicle/fiat
- https://stackoverflow.com/questions/4356289/php-random-string-generator

Initial upload of api file. 

Status:
- So far it is tested until the getVehicles-Request.
- getVehicleStatus and getVehicleLocation will be tested as soon we received our Fiat car.
- Command requests to come later.