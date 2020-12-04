# ac-signature PHP

This module helps you to sign request for the AdmiralCloud media asset management.
https://www.admiralcloud.com

Please note, that every signed payload is only valid for 10 seconds by default. The same is true for time deviation (+/- 10 seconds), so make sure your computer's time is in sync/valid. You can set the deviation with a custom value using options

ATTN: This is a preliminary version. If you want to use it in production, please contact our support first!


## Usage

```
<?php
include_once('./index.php');

$acsign = new acSignature();


$accessKey = "PROVIDED BY ADMIRALCLOUD";
$accessSecret = "PROVIDED BY ADMIRALCLOUD;

$params = array(
  "accessSecret" =>  $accessSecret,
  "controller" =>   "me",
  "action" =>       "find",
  "payload" => array(
    "id" => 123
  )
);
$signedValues = $acsign->sign($params);
// signedValues contains "timestamp" and "hash"
?>
```

## Prerequisites
You need to provide the following parameters for this function:

accessSecret
AccessKey and AccessSecret for your user in AdmiralCloud. Please contact support@admiralcloud.com for this information.

controller
The controller you are requesting. Please see API documentation

action
The action you are requesting. Please see API documentation.

payload
The actual payload you want to send to the API.

# Examples
For the following examples, we assume, that your accessKey "AKAC12344321" and you accessSecret is "my-very-good-accessSecret".


## Sign a request
```
<?php
include_once('./index.php');

$acsign = new acSignature();


$accessKey = "AKAC12344321";
$accessSecret = "my-very-good-accessSecret

$params = array(
  "accessSecret" =>  $accessSecret,
  "controller" =>   "user",
  "action" =>       "find",
  "payload" => array(
    "id" => 123
  )
);
$signedValues = $acsign->sign($params);
// signedValues contains "timestamp" and "hash"

curl --location --request GET 'https://api.admiralcloud.com/v5/user/123' \
--header 'X-AdmiralCloud-AccessKey: $accessKey \
--header 'X-AdmiralCloud-rts: $signedValues["timestamp"] \
--header 'X-AdmiralCloud-hash: $signedValues["hash"] \

?>

```


# Options
Option | Type | Remarks
---|---|---|
deviation | number | Number in seconds, RTS/time deviation is allowed. If the timestamp is out of range, the request will fail


# Links
- [Website](https://www.admiralcloud.com/)
- [Twitter (@admiralcloud)](https://twitter.com/admiralcloud)
- [Facebook](https://www.facebook.com/MediaAssetManagement/)

# Run tests
TBC

## License

[MIT License](https://opensource.org/licenses/MIT) Copyright © 2009-present, AdmiralCloud, Mark Poepping