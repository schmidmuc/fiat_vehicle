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
	private string			$awsCredentialsSessionToken;
	private string			$awsCredentialsUserID;

	private string			$awsApiUrl  					= "https://channels.sdpr-01.fcagcv.com";
	private string			$awsService						= "execute-api";
	private string			$awsRegion						= "eu-west-1";

	private array			$vehicles;

	private string			$log							= "";



    public function __construct ( string $user, string $password ) {

        $this->fiatLoginUser 				= $user;
        $this->fiatLoginPassword 			= $password;

		$this->fiatLoginSessionExpiration	= 7776000;
		$this->awsAuthClientRequestID 		= getRandomClientRequestID();

    }



	private function callApiFiatWebSDK () {

		$this->log .= "<b>WebSDK</b> = ".$this->fiatWebSdkUrl."\n<br>";

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
		));

		$response = curl_exec($curl);

		curl_close($curl);

		$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".$response."\n<br>";

	}



	private function callApiFiatLogin () {

		$this->log .= "<b>Fiat Login</b> = ".$this->fiatLoginUrl."\n<br>";

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
			
			),
		));
		
		$response = curl_exec($curl);
		
		curl_close($curl);
		$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".$response."\n<br>";
		
		$responseRaw = json_decode($response, true);
		$this->fiatLoginToken = $responseRaw['sessionInfo']['login_token'];
		$this->fiatLoginUID = $responseRaw['UID'];
		
		$_SESSION['fiatLoginUID'] = $this->fiatLoginUID;

		$this->log .= "&#9733; fiatLoginToken = ".$this->fiatLoginToken."\n<br>";
		$this->log .= "&#9733; fiatLoginUID = ".$this->fiatLoginUID."\n<br>";
	}



	private function callApiFiatJWT () {

		$this->log .= "<b>Fiat JWT</b> = ".$this->fiatJwtUrl."\n<br>";

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
			CURLOPT_CUSTOMREQUEST 	=> 	'GET',
		  ));
		
		$response = curl_exec($curl);

		curl_close($curl);
		$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".$response."\n<br>";

		$responseRaw = json_decode($response, true);
		$this->fiatJwtIdToken = $responseRaw['id_token'];

		$this->log .= "&#9733; fiatJwtIdToken = ".$this->fiatJwtIdToken."\n<br>";

	}




	private function callApiAmazonCognito () {

		$this->log .= "<b>awsAuthUrl</b> = ".$this->awsAuthUrl."\n<br>";

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
		$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".$response."\n<br>";

		$responseRaw = json_decode($response, true);
		$this->awsAuthIdentityID = $responseRaw['IdentityId'];
		$this->awsAuthToken = $responseRaw['Token'];

		$this->log .= "&#9733; awsAuthIdentityID = ".$this->awsAuthIdentityID."\n<br>";
		$this->log .= "&#9733; awsAuthToken = ".$this->awsAuthToken."\n<br>";

	}




	private function callApiAmazonGetCredentials () {

		$this->log .= "<b>cognitoidentity.GetCredentialsForIdentityOutput</b> = ".$this->awsAuthUrl."\n<br>";
		
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
		
		$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".$response."\n<br>";
		
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
		
		$this->appendToLog ( "&#9733; awsCredentialsAccessKeyId = ".$this->awsCredentialsAccessKeyId."\n<br>" );
		$this->appendToLog ( "&#9733; awsCredentialsExpiration = ".$this->awsCredentialsExpiration."\n<br>" );
		$this->appendToLog ( "&#9733; awsCredentialsSecretKey = ".$this->awsCredentialsSecretKey."\n<br>" );
		$this->appendToLog ( "&#9733; awsCredentialsSessionToken = ".$this->awsCredentialsSessionToken."\n<br>" );

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
	
	
	
	public function getVehicles () {

		$this->renewAmazonGetCredentialsIfNecessary();

		$this->log .= "<b>Vehicles</b> = ".$this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles?stage=ALL\n<br>";

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

		$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".($response->getBody())."\n<br>";

		$responseRaw = json_decode( ($response->getBody()), true );

		$this->vehicles = $responseRaw['vehicles'];
		$this->awsCredentialsUserID = $responseRaw['userid'];

		$this->log .= "&nbsp;&nbsp;&nbsp; Vehicles = ".implode(" ", $this->vehicles)."\n<br>";

	}



	public function getVehicleStatus ( $vin ) {

		$this->renewAmazonGetCredentialsIfNecessary();

		$this->log .= "<b>Vehicle Status</b> = ".$this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/status\n<br>";

		
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
   
	   	$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".($response->getBody())."\n<br>";

	}



	public function getVehicleLocation ( $vin ) {

		$this->renewAmazonGetCredentialsIfNecessary();

		$this->log .= "<b>Vehicle Location</b> = ".$this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/location/lastknown\n<br>";

		$request = new GuzzleHttp\Psr7\Request(
			'GET',
			$this->awsApiUrl."/v4/accounts/".$this->fiatLoginUID."/vehicles/".$vin."/location/lastknown",
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
   
	   	$this->log .= "&nbsp;&nbsp;&nbsp; Response = ".($response->getBody())."\n<br>";

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



	public function appendToLog ( $log ) {

		$this->log .= $log;

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

}