<?php

require_once '/var/www/html/vendor/autoload.php';

use Aws\Credentials\Credentials;
use Aws\Signature\SignatureV4;
use Psr\Http\Message\RequestInterface;
use Aws\CognitoIdentity\CognitoIdentityClient;

/**
 * apiFiat
 */
class apiFiat {

	private string			$fiatApiKey						= "3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI";

	private string			$fiatWebSdkUrl					= "https://loginmyuconnect.fiat.com/accounts.webSdkBootstrap";

	private string			$fiatLoginUrl					= "https://loginmyuconnect.fiat.com/accounts.login";
	private int				$fiatLoginSessionExpiration;
	private string			$fiatLoginUser;
	private string			$fiatLoginPassword;
	private string			$fiatLoginToken;
	private string			$fiatLoginUID;
	private					$fiatCookieJar;

	private string			$fiatJwtUrl						= "https://loginmyuconnect.fiat.com/accounts.getJWT";
	private string			$fiatJwtIdToken;

	private string			$awsAuthUrl						= "https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token";
	private string			$awsAuthXApiKey					= "qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je";
	private string			$awsAuthClientRequestID;
	private string			$awsAuthIdentityID;
	private string			$awsAuthToken;

	private string			$awsCredentialsAccessKeyId;
	private string			$awsCredentialsExpiration;
	private string			$awsCredentialsSecretKey;
	private string			$awsCredentialsSessionToken		= "";
	private string			$awsCredentialsUserID;

	private string			$awsApiUrl  					= "https://channels.sdpr-01.fcagcv.com";
	private string			$awsService						= "execute-api";
	private string			$awsRegion						= "eu-west-1";

	private array			$vehicles;
	private array			$vehicleStatus;

	private array			$logArray;



    public function __construct ( string $user, string $password ) {

        $this->fiatLoginUser 				= $user;
        $this->fiatLoginPassword 			= $password;

		$this->fiatLoginSessionExpiration	= 7776000;
		$this->awsAuthClientRequestID 		= $this->getRandomClientRequestID();

		$this->logArray						= array();
		$this->vehicles						= array();
		$this->vehicleStatus				= array();

		$this->fiatCookieJar				= tempnam('/tmp','cookieFiat');

		$this->appendToLogArray ( "Temporary cookie file created", $this->fiatCookieJar, 2 );

    }



	private function callApiFiatWebSDK () {

		$this->appendToLogArray ( "WebSDK", $this->fiatWebSdkUrl, 2, 1 );

		$curl = curl_init();

		curl_setopt_array($curl, array(

			CURLOPT_URL 			=> 	$this->fiatWebSdkUrl.'?apiKey='.$this->fiatApiKey,
			CURLOPT_RETURNTRANSFER 	=> 	true,
			CURLOPT_ENCODING 		=> 	'',
			CURLOPT_MAXREDIRS 		=> 	10,
			CURLOPT_TIMEOUT 		=> 	0,
			CURLOPT_FOLLOWLOCATION 	=> 	true,
			CURLOPT_HTTP_VERSION 	=> 	CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST 	=> 	'GET',
			CURLOPT_COOKIEJAR		=>	$this->fiatCookieJar,
			// CURLOPT_HTTPHEADER => array(
			//   'Cookie: ASP.NET_SessionId=til3lzkz3kdqas14lehwq0sm; gmid=gmid.ver4.AcbHk6LF-w.mSDIL-OQ0kWBFotQ2YipdQYB7E7-SJmCxvyOx17OTZbXPEMSsOhyWZ0kdDov9fOV.JA4W5L23nJwCCaRi9qTzVhDeJllPyrw5XNoMqGh51-vECLTZH_PTkjfG42orCYwsSXpUBCpC4mPQjfh1eVEHBg.sc3; hasGmid=ver4; ucid=vthVogPt1lCCjnSIR8M6nw'
			// ),
		));

		$response = curl_exec($curl);

		curl_close($curl);

		$this->appendToLogArray ( "Response", $response, 2, 2 );

	}



	private function callApiFiatLogin () {

		$this->appendToLogArray ( "Fiat Login", $this->fiatLoginUrl, 2, 1 );

		$curl = curl_init();

		curl_setopt_array($curl, array(

			CURLOPT_URL 			=> 	$this->fiatLoginUrl,
			CURLOPT_RETURNTRANSFER 	=> 	true,
			CURLOPT_ENCODING 		=> 	'',
			CURLOPT_MAXREDIRS 		=> 	10,
			CURLOPT_TIMEOUT 		=> 	0,
			CURLOPT_FOLLOWLOCATION 	=> 	true,
			CURLOPT_HTTP_VERSION 	=> 	CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST 	=> 	'POST',
			CURLOPT_COOKIEFILE		=>	$this->fiatCookieJar,
			CURLOPT_POSTFIELDS 		=>	'loginID='.$this->fiatLoginUser.'&'.
										'password='.$this->fiatLoginPassword.'&'.
										'sessionExpiration='.$this->fiatLoginSessionExpiration.'&'.
										'APIKey='.$this->fiatApiKey.'&'.
										'pageURL=https%3A%2F%2Fmyuconnect.fiat.com%2Fde%2Fde%2Flogin&'.
										'sdk=js_latest&'.
										'sdkBuild=12234&'.
										'format=json&'.
										'targetEnv=jssdk&'.
										'include=profile%2Cdata%2Cemails%2Csubscriptions%2Cpreferences&'.
										'includeUserInfo=true&'.
										'loginMode=standard&'.
										'lang=de0de&'.
										'source=showScreenSet&'.
										'authMode=cookie',
			CURLOPT_HTTPHEADER 		=> 	array(

				'Content-Type: application/x-www-form-urlencoded',
				//'Cookie: ASP.NET_SessionId=til3lzkz3kdqas14lehwq0sm; gmid=gmid.ver4.AcbHk6LF-w.mSDIL-OQ0kWBFotQ2YipdQYB7E7-SJmCxvyOx17OTZbXPEMSsOhyWZ0kdDov9fOV.JA4W5L23nJwCCaRi9qTzVhDeJllPyrw5XNoMqGh51-vECLTZH_PTkjfG42orCYwsSXpUBCpC4mPQjfh1eVEHBg.sc3; hasGmid=ver4; ucid=vthVogPt1lCCjnSIR8M6nw'
			  
			
			),
		));
		
		$response = curl_exec($curl);
		
		curl_close($curl);
		$this->appendToLogArray ( "Response", $response, 2, 2 );
		
		$responseRaw = json_decode($response, true);
		$this->fiatLoginToken = $responseRaw['sessionInfo']['login_token'];
		$this->fiatLoginUID = $responseRaw['UID'];
		
		$_SESSION['fiatLoginUID'] = $this->fiatLoginUID;

		$this->appendToLogArray ( "fiatLoginToken", $this->fiatLoginToken, 3, 2 );
		$this->appendToLogArray ( "fiatLoginUID", $this->fiatLoginUID, 3, 2 );
	}



	private function callApiFiatJWT () {

		$this->appendToLogArray ( "Fiat JWT", $this->fiatJwtUrl, 2, 1 );

		$curl = curl_init();

		curl_setopt_array($curl, array(

			CURLOPT_URL 			=> 	$this->fiatJwtUrl.'?'.
										'APIKey='.$this->fiatApiKey.'&'.
										'pageURL=https://myuconnect.fiat.com/de/de/dashboard&'.
										'sdk=js_latest&'.
										'sdkBuild=12234&'.
										'format=json&'.
										'login_token='.$this->fiatLoginToken.'&'.
										'authMode=cookie&fields=profile.firstName,profile.lastName,profile.email,country,locale,data.disclaimerCodeGSDP',
			CURLOPT_RETURNTRANSFER 	=> 	true,
			CURLOPT_ENCODING 		=> 	'',
			CURLOPT_MAXREDIRS 		=> 	10,
			CURLOPT_TIMEOUT 		=> 	0,
			CURLOPT_FOLLOWLOCATION 	=> 	true,
			CURLOPT_HTTP_VERSION 	=> 	CURL_HTTP_VERSION_1_1,
			CURLOPT_COOKIEFILE		=>	$this->fiatCookieJar,
			CURLOPT_CUSTOMREQUEST 	=> 	'GET',
			//CURLOPT_HTTPHEADER => array(
			//  'Cookie: ASP.NET_SessionId=til3lzkz3kdqas14lehwq0sm; gmid=gmid.ver4.AcbHk6LF-w.mSDIL-OQ0kWBFotQ2YipdQYB7E7-SJmCxvyOx17OTZbXPEMSsOhyWZ0kdDov9fOV.JA4W5L23nJwCCaRi9qTzVhDeJllPyrw5XNoMqGh51-vECLTZH_PTkjfG42orCYwsSXpUBCpC4mPQjfh1eVEHBg.sc3; hasGmid=ver4; ucid=vthVogPt1lCCjnSIR8M6nw'
			//),
		  ));
		
		$response = curl_exec($curl);

		curl_close($curl);
		$this->appendToLogArray ( "Response", $response, 2, 2 );

		$responseRaw = json_decode($response, true);
		if ( $responseRaw['id_token'] ) {
		
			$this->fiatJwtIdToken = $responseRaw['id_token'];

			$this->appendToLogArray ( "fiatJwtIdToken", $this->fiatJwtIdToken, 3, 2 );

		}

	}




	private function callApiAmazonCognito () {

		$this->appendToLogArray ( "awsAuthUrl", $this->awsAuthUrl, 2, 1 );

		$curl = curl_init();

		curl_setopt_array($curl, array(

			CURLOPT_URL 			=> 	$this->awsAuthUrl,
			CURLOPT_RETURNTRANSFER 	=> 	true,
			CURLOPT_ENCODING 		=> 	'',
			CURLOPT_MAXREDIRS 		=> 	10,
			CURLOPT_TIMEOUT 		=> 	0,
			CURLOPT_FOLLOWLOCATION 	=> 	true,
			CURLOPT_HTTP_VERSION 	=> 	CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST 	=> 	'POST',
			CURLOPT_POSTFIELDS 		=>	'{

				"gigya_token": "'.$this->fiatJwtIdToken.'"

			}',
			CURLOPT_HTTPHEADER 		=> 	array(

				'x-clientapp-version: 1.0',
				'clientrequestid: '.$this->awsAuthClientRequestID,
				'X-Api-Key: '.$this->awsAuthXApiKey,
				'x-originator-type: web',
				'x-clientapp-name: CWP',
				'Content-Type: application/json'

			),
		));

		$response = curl_exec($curl);

		curl_close($curl);
		$this->appendToLogArray ( "Response", $response, 2, 2 );

		$responseRaw = json_decode($response, true);
		$this->awsAuthIdentityID = $responseRaw['IdentityId'];
		$this->awsAuthToken = $responseRaw['Token'];

		$this->appendToLogArray ( "awsAuthIdentityID", $this->awsAuthIdentityID, 3, 2 );
		$this->appendToLogArray ( "awsAuthToken", $this->awsAuthToken, 3, 2 );

	}




	private function callApiAmazonGetCredentials () {

		$this->appendToLogArray ( "cognitoidentity.GetCredentialsForIdentityOutput", $this->awsAuthUrl, 2, 1 );
		
		// The AWS client is relying on these being retrieved via `getenv` and DotEnv no longer sets via `putenv`
		putenv("AWS_ACCESS_KEY_ID=ABC");
		putenv("AWS_SECRET_ACCESS_KEY=DEF");
		
		$client = CognitoIdentityClient::factory(array(

			'region'  => $this->awsRegion,
			'version' => '2014-06-30'

		));
		
		$response = $client->getCredentialsForIdentity(array(

			// IdentityId is required
			'IdentityId' => $this->awsAuthIdentityID,
			'Logins' => array(

				// Associative array of custom 'IdentityProviderName' key names
				'cognito-identity.amazonaws.com' => $this->awsAuthToken

			),
		));
		
		$this->appendToLogArray ( "Response", $response, 2, 2 );
		
		$posJSON = strpos ( $response, "{" );
		$responseRaw = json_decode( substr ($response, $posJSON), true);
		
		$Credentials = $responseRaw['Credentials'];
		
		$this->awsCredentialsAccessKeyId = $Credentials['AccessKeyId'];
		$this->awsCredentialsExpiration = $Credentials['Expiration'];
		$this->awsCredentialsSecretKey = $Credentials['SecretKey'];
		$this->awsCredentialsSessionToken = $Credentials['SessionToken'];

		$_SESSION['awsCredentialsAccessKeyId'] = $Credentials['AccessKeyId'];
		$_SESSION['awsCredentialsExpiration'] = $Credentials['Expiration'];
		$_SESSION['awsCredentialsSecretKey'] = $Credentials['SecretKey'];
		$_SESSION['awsCredentialsSessionToken'] = $Credentials['SessionToken'];
		
		$this->appendToLogArray ( "awsCredentialsAccessKeyId", $this->awsCredentialsAccessKeyId, 3, 2 );
		$this->appendToLogArray ( "awsCredentialsExpiration", $this->awsCredentialsExpiration, 3, 2 );
		$this->appendToLogArray ( "awsCredentialsSecretKey", $this->awsCredentialsSecretKey, 3, 2 );
		$this->appendToLogArray ( "awsCredentialsSessionToken", $this->awsCredentialsSessionToken, 3, 2 );

	}



	public function checkValidityAmazonGetCredentials () {

		if ( strtotime($_SESSION['awsCredentialsExpiration']) < time () ) {

			return false;

		}
		else {

			return true;

		}
		
	}



	public function renewAmazonGetCredentialsIfNecessary () {

		if (	strtotime($_SESSION['awsCredentialsExpiration']) < time () ||
				!isset ($_SESSION['fiatLoginUID']) ) {

			$this->refreshLogin();

		}
		else {
			
			$this->awsCredentialsAccessKeyId = $_SESSION['awsCredentialsAccessKeyId'];
			$this->awsCredentialsExpiration = $_SESSION['awsCredentialsExpiration'];
			$this->awsCredentialsSecretKey = $_SESSION['awsCredentialsSecretKey'];
			$this->awsCredentialsSessionToken = $_SESSION['awsCredentialsSessionToken'];
			$this->fiatLoginUID = $_SESSION['fiatLoginUID'];
			
		}
		
	}
	
	
	
	public function apiRequestVehicles () {

		$this->renewAmazonGetCredentialsIfNecessary();

		$this->appendToLogArray ( "Vehicles", $this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles?stage=ALL", 2, 1 );

		if ( $this->awsCredentialsSessionToken ) {

			$request = new GuzzleHttp\Psr7\Request (
				'GET',
				$this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles?stage=ALL",
				[  'Content-Type' => 'application/json',
				'x-clientapp-version' => '1.0',
				'clientrequestid' => '1592674815357357',
				'X-Api-Key' => $this->awsAuthXApiKey,
				'x-originator-type' => 'web',
				'locale' => 'de_de',
				'X-Amz-Security-Token' => $this->awsCredentialsSessionToken
			]
			);
			$signed_request = $this->sign($request, $this->awsCredentialsAccessKeyId, $this->awsCredentialsSecretKey);
		
			$client = new \GuzzleHttp\Client();
			$response = $client->send($signed_request);

			$this->appendToLogArray ( "Response", ($response->getBody()), 2, 2 );

			$responseRaw = json_decode( ($response->getBody()), true );

			$this->vehicles = $responseRaw['vehicles'];
			$this->awsCredentialsUserID = $responseRaw['userid'];

			$this->appendToLogArray ( "Vehicles", implode(" ", $this->vehicles), 2, 2 );

		}
		else {

			$this->appendToLogArray ( "Failure", "awsCredentialsSessionToken not set", 5, 2 );

		}

	}



	public function apiRequestVehicleStatus ( $vin ) {

		$this->renewAmazonGetCredentialsIfNecessary();

		$this->appendToLogArray ( "Vehicles", $this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/status", 2, 1 );

		
		$request = new GuzzleHttp\Psr7\Request(
			'GET',
			$this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/status",
			[  'Content-Type' => 'application/json',
			   'x-clientapp-version' => '1.0',
			   'clientrequestid' => '1592674815357357',
			   'X-Api-Key' => 'qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je',
			   'x-originator-type' => 'web',
			   'locale' => 'de_de',
			   'X-Amz-Security-Token' => $this->awsCredentialsSessionToken
		   ]
		);
		$signed_request = sign($request, $this->awsCredentialsAccessKeyId, $this->awsCredentialsSecretKey);
   
		$client = new \GuzzleHttp\Client();
		$response = $client->send($signed_request);

		$this->appendToLogArray ( "Response", ($response->getBody()), 2, 2 );

		$responseRaw = json_decode( ($response->getBody()), true );

		$this->vehicleStatus[$vin]['Status'] = $responseRaw;

	}



	public function apiRequestVehicleLocation ( $vin ) {

		$this->renewAmazonGetCredentialsIfNecessary();

		$this->appendToLogArray ( "Vehicles", $this->awsApiUrl."/v1/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/location/lastknown", 2, 1 );

		$request = new GuzzleHttp\Psr7\Request(
			'GET',
			$this->awsApiUrl."/v1/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/location/lastknown",
			[  'Content-Type' => 'application/json',
			   'x-clientapp-version' => '1.0',
			   'clientrequestid' => '1592674815357357',
			   'X-Api-Key' => 'qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je',
			   'x-originator-type' => 'web',
			   'locale' => 'de_de',
			   'X-Amz-Security-Token' => $this->awsCredentialsSessionToken
		   ]
		);
		$signed_request = sign($request, $this->awsCredentialsAccessKeyId, $this->awsCredentialsSecretKey);
   
		$client = new \GuzzleHttp\Client();
		$response = $client->send($signed_request);

		$this->appendToLogArray ( "Response", ($response->getBody()), 2, 2 );

		$responseRaw = json_decode( ($response->getBody()), true );

		$this->vehicleStatus[$vin]['Location'] = $responseRaw;

	}



	public function apiRequestAll () {

		$this->apiRequestVehicles ();

		if ( is_array($this->vehicles) ) {

			foreach ($this->vehicles as $vehicle) {
			
				$this->apiRequestVehicleStatus ( $vehicle['vin'] );
				$this->apiRequestVehicleLocation ( $vehicle['vin'] );
			
			}
		}
	}



	public function exportInformation () {

		$exportArray = array (

			"vehicles"	=>	$this->vehicles,
			"vehicle"	=>	$this->vehicleStatus

		);

		return json_encode ( $exportArray );

	}



	public function getVehicleStatusData ( $vin, $level1, $level2 = "", $level3 = "", $level4 = "", $level5 = "" ) {

		// first draft, has to be validated with real data

		if ( $level1 != "" && $level2 != "" && $level3 != "" && $level4 != "" && $level5 ) {

			$return = $this->vehicleStatus[$level1][$level2][$level3][$level4][$level5];

		}
		if ( $level1 != "" && $level2 != "" && $level3 != "" && $level4 != "" ) {

			$return = $this->vehicleStatus[$level1][$level2][$level3][$level4];

		}
		if ( $level1 != "" && $level2 != "" && $level3 != "" ) {

			$return = $this->vehicleStatus[$level1][$level2][$level3];

		}
		if ( $level1 != "" && $level2 != "" ) {

			$return = $this->vehicleStatus[$level1][$level2];

		}
		if ( $level1 != "" ) {

			$return = $this->vehicleStatus[$level1];

		}

		if ( is_array ( $return )) {

			return json_encode ( $return );

		}
		else {

			return $return;

		}

	}



	public function refreshLogin () {

		$this->callApiFiatWebSDK();
		$this->callApiFiatLogin();
		$this->callApiFiatJWT();
		$this->callApiAmazonCognito();
		$this->callApiAmazonGetCredentials();

	}



	public function getLog () {

		return $this->log;

	}



	public function getLogArray ( $asJSON = true ) {

		if ( $asJSON ) {
		
			return json_encode ($this->logArray);

		}
		else {

			return $this->logArray;

		}
	}



	public function sign (
		RequestInterface $request,
		string $accessKeyId,
		string $secretAccessKey
	): RequestInterface {

		$signature = new SignatureV4 ( $this->awsService, $this->awsRegion );
		$credentials = new Credentials ( $accessKeyId, $secretAccessKey );
	
		return $signature->signRequest( $request, $credentials );

	}



	private function getRandomClientRequestID ( $length = 16 ) {

		$characters = '0123456789abcdefghijklmnopqrstuvwxyz';
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;

	}



	private function appendToLogArray ( $topic, $message, $level = 1, $hierarchie = 1 ) {

		array_push ( $this->logArray, array (

			'timestamp'		=>	time(),
			'hierarchie'	=>	$hierarchie,
			'topic'			=>	$topic,
			'message'		=>	$message,
			'level'			=>	$level

		));

	}

}
