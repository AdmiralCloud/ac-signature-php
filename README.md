# ac-signature PHP

This module helps you to sign requests for the AdmiralCloud media asset management.
https://www.admiralcloud.com

Please note that every signed payload is only valid for 10 seconds by default. The same is true for time deviation (+/- 10 seconds), so make sure your computer's time is in sync/valid. You can set the deviation with a custom value using options.

**ATTENTION: Signature versions prior to version 5 will not be supported by AdmiralCloud API after 2025-07-01.**

Please check https://github.com/AdmiralCloud/ac-signature for a NodeJS version of this package.


# Prerequisites
You need to provide the following parameters for this function:

* accessSecret: AccessSecret for your user in AdmiralCloud. Please contact AC team for this information.
* accessKey: Your AccessKey from AdmiralCloud, used for debugging.
* path: The API endpoint path you are requesting (e.g., "/v5/search")
* payload: The actual payload (JSON) you want to send to the API.
* identifier: (Optional) Identifier header for requests made "on behalf" of another entity. Please contact AC team if you want to use it.

# Installation
## Using Composer (Recommended)
The easiest way to install ac-signature is using Composer. Add this to your composer.json file:
```
{
    "require": {
        "admiralcloud/ac-signature": "^5.0"
    }
}

// execute
composer require admiralcloud/ac-signature

// In your PHP code

require_once 'vendor/autoload.php';
use AdmiralCloud\AcSignature\acSignature;

$acsign = new acSignature();
```

## Manual Installation
If you're not using Composer, you can include the file directly:

Download the acSignature.php file from our repository, place it in your project directory and include it in your PHP code

```
require_once 'path/to/acSignature.php';
$acsign = new acSignature();
```

Requirements

PHP 7.0 or higher
PHP hash extension (usually included by default)

# Usage
See "Installation" on how to make $acsign available in your code.

```
<?php
$accessKey = "PROVIDED BY ADMIRALCLOUD";
$accessSecret = "PROVIDED BY ADMIRALCLOUD";

$params = array(
    "accessSecret" => $accessSecret,
    "accessKey" => $accessKey,
    "path" => "/v5/search",
    "payload" => array(
        "searchTerm" => "My new video"
    ),
    "identifier" => "optional-identifier" // optional, please contact our team before you start using this identifier
);

$signedValues = $acsign->sign5($params);
// signedValues contains "timestamp" and "hash"
?>
```

## Example
For this example, we assume your accessKey is "AKAC12344321" and your accessSecret is "my-very-good-accessSecret".
```
<?php
$accessKey = "AKAC12344321";
$accessSecret = "my-very-good-accessSecret";

$params = array(
    "accessSecret" => $accessSecret,
    "accessKey" => $accessKey,
    "path" => "/v5/search",
    "payload" => array(
        "searchTerm" => "My new video"
    )
);

$signedValues = $acsign->sign5($params);

// Use the signed values in your API request
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => 'https://api.admiralcloud.com/v5/user/123',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => json_encode($params['payload']),
    CURLOPT_HTTPHEADER => array(
        'Content-Type: application/json',
        'x-admiralcloud-clientId: ' . $clientId, // ClientID of your application, contact AC team if you are not sure about it
        'x-admiralcloud-accesskey: ' . $accessKey,
        'x-admiralcloud-rts: ' . $signedValues["timestamp"],
        'x-admiralcloud-hash: ' . $signedValues["hash"],
        'x-admiralcloud-version: 5',
        'x-admiralcloud-identifier: ' . $identifier // if used in signature, you have to send it as well.
    )
));
?>
```

## Options
Option | Type | Remarks
---|---|---|
deviation | number | Number in seconds, RTS/time deviation is allowed. If the timestamp is out of range, the request will fail

# Tests
We are using Docker container to run the tests. Run **docker-compose up --build**.

# Links
* [AdmiralCloud Website](https://www.admiralcloud.com/)
* [Developer Platform](https://developer.admiralcloud.com)

# License
MIT License **Copyright © 2009-present, AdmiralCloud AG, Mark Poepping