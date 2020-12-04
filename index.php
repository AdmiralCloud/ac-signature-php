<?php

class acSignature
{

    public function sign($params)
    {
      $accessSecret = $params['accessSecret'];
      if (!$accessSecret) return 'accessSecretMissing';
      $controller = $params['controller'];
      if (!$controller) return 'controllerMissing';
      $action = $params['action'];
      if (!$action) return 'actionMissing';
      $data = $params['payload'];
      if (!$data) return 'payloadMustBeObject';
      // for debugging
      $accessKey = isset($params['accessKey']) ? $params['accessKey'] : null; // only for debugging
  
      ksort($data);
      $payload = array();
      foreach ($data as $key => $value) {
          $payload[$key] = $data[$key];
      }

      $ts = !isset($params['ts']) ? time() : $params['ts'];
      $valueToHash = strtolower($controller) . PHP_EOL .
                     strtolower($action) . PHP_EOL . 
                     $ts . 
                     (empty($payload) ? '' : PHP_EOL . json_encode($payload));
      $hash = hash_hmac('sha256', $valueToHash, $accessSecret);
  
      if (isset($params['debug'])) {
        $debugPadding = 20;
        echo str_repeat( '_', 80) . PHP_EOL;
        echo str_pad( 'Sign payload', 80) . "\n";        
        echo str_pad( 'Access Key', $debugPadding ) . $accessKey . "\n";
        echo str_pad( 'Controller/Action', $debugPadding ) . $controller . '/' . $action . PHP_EOL;
        echo str_pad( 'Payload to hash', $debugPadding ) . preg_replace( "/\n/", "/", $valueToHash ) . PHP_EOL;
        echo str_pad( 'Lenght', $debugPadding ) . strlen($valueToHash) . "\n";
        echo str_pad( 'TS', $debugPadding ) . $ts . "\n";
        echo str_pad( 'Calculated hash', $debugPadding ) . $hash . "\n";
        echo str_repeat( '_', 80) . PHP_EOL;
        echo PHP_EOL;
      }

      return [
          'hash' => $hash,
          'timestamp' => $ts,
          'valueToHash' => $valueToHash
      ];  
    }

    public function checkSignedPayload($params, $options)
    {
      if (!$options) throw new Exception('optionsRequired');
      $headers = !isset($options['headers']) ? array(
        "x-admiralcloud-hash" => null,
        "x-admiralcloud-accessKey" => null,
        "x-admiralcloud-rts" => null,
        "x-admiralcloud-debugSignature" => null      
      ) : $options['headers'];

      $method = $options['method'];
      $controller = strtolower($options['controller']);
      $action = strtolower($options['action']);
      $accessSecret = $options['accessSecret'];
      $deviation = !isset($options['deviation']) ? 10 : $options['deviation'];
     
      // determine by headers
      $hash = !isset($options['hash']) ? $headers['x-admiralcloud-hash'] : $options['hash'];
      $accessKey = !isset($options['accessKey']) ? $headers['x-admiralcloud-accessKey'] : $options['accessKey'];
      $ts = !isset($options['rts']) ? (int) $headers['x-admiralcloud-rts'] : $options['rts'];  
      $debugSignature = !isset($options['debugSignature']) ? $headers['x-admiralcloud-debugSignature'] : $options['debugSignature'];
      $errorPrefix = !isset($options['errorPrefix']) ? 'acsignature' : $options['errorPrefix'];

  
      if (!$hash) {
        $error = array("message" =>  $errorPrefix . '_hashMissing', "status" => 401 );
        return $error;
      }
  
      if ($deviation) {
        $min = time() - $deviation;
        $max = time() + $deviation;
        if ($ts < $min || $ts > $max) {
          $error = array("message" => $errorPrefix . '_rtsDeviation', "status" => 401);
          return $error;
        }
      } 
  
      // GET request send parameters as string instead of integer -> parse that here (see route.js for parameters)
      if ($method === 'GET') {
        foreach ($params as $key => $value) {
          if ($value === (int) $value) {
            $params[$key] = (int) $value;
          }
        }
      }

      $signParams = array(
        "accessSecret" => $accessSecret,
        "controller" => $controller,
        "action" => $action,
        "payload" => $params,
        "ts" => $ts
      );
      
      $signedPayload = $this->sign($signParams);
  
      if (isset($debugSignature) || $signedPayload["hash"] !== $hash) {
        $debugPadding = 20;
        echo str_repeat( '_', 80) . PHP_EOL;
        echo str_pad( 'Check Signature', 80) . "\n";
        echo str_pad( 'Access Key', $debugPadding ) . $accessKey . "\n";
        echo str_pad( 'Controller/Action', $debugPadding ) . $controller . '/' . $action . PHP_EOL;
        echo str_pad( 'Payload to hash', $debugPadding ) . preg_replace( "/\n/", "/", $signedPayload['valueToHash'] ) . PHP_EOL;
        echo str_pad( 'Lenght', $debugPadding ) . strlen($signedPayload['valueToHash']) . "\n";
        echo str_pad( 'TS', $debugPadding ) . $ts . "\n";
        echo str_pad( 'Expected hash', $debugPadding ) . $hash . "\n";
        echo str_pad( 'Calculated hash', $debugPadding ) . $signedPayload["hash"] . "\n";
        echo str_repeat( '_', 80) . PHP_EOL;
        echo PHP_EOL;
      }

      if ($signedPayload["hash"] !== $hash) {
        return array("message" => $errorPrefix . "_hashMismatch", "status" => 401);
      }
    }
}