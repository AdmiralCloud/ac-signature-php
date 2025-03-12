<?php

class acSignature
{
    private $debugPrefix = 'ACSignature';
    private $debugPadding = 20;

    /**
     * Sign with version 5
     */
    public function sign5($params)
    {
        return $this->sign($params, ['version' => 5]);
    }

    /**
     * Sign with version 2
     */
    public function sign2($params)
    {
        return $this->sign($params, ['version' => 2]);
    }

    /**
     * Main signing function
     */
    public function sign($params, $options = [])
    {
        $accessSecret = $params['accessSecret'];
        if (!$accessSecret) return 'accessSecretMissing';

        // accessKey only required for debugging
        $accessKey = isset($params['accessKey']) ? $params['accessKey'] : null;
        $data = isset($params['payload']) && is_array($params['payload']) ? $params['payload'] : [];
        $path = isset($params['path']) ? explode('?', $params['path'])[0] : ''; // make sure the path is just the path
        $identifier = isset($params['identifier']) ? $params['identifier'] : null; // identifier header for requests "on behalf"
        
        $ts = isset($params['ts']) ? $params['ts'] : time();
        $debugMode = isset($params['debug']) ? $params['debug'] : false;
        $version = isset($options['version']) ? $options['version'] : 1;

        if ($debugMode) {
            echo str_pad("Create Signature V{$version}", 80, '-') . PHP_EOL;
            if ($accessKey) {
                echo str_pad($this->debugPrefix, 14) . " | " . 
                     str_pad("API Key", $this->debugPadding) . " | " . 
                     $accessKey . PHP_EOL;
            }
        }

        $payload = [];
        if ($version < 3) {
            // sort order fileName, filename
            $keys = array_keys($data);
            sort($keys);
            foreach ($keys as $key) {
                $payload[$key] = $data[$key];
            }
        } else {
            $payload = $this->deepSortObjectKeys($data);
        }

        if ($version >= 2 && $path) {
            // version 2 with path only
            $valueToHash = strtolower($path);
            if ($debugMode) {
                echo str_pad($this->debugPrefix, 14) . " | " . 
                     str_pad("Path", $this->debugPadding) . " | " . 
                     $path . PHP_EOL;
            }
        } else {
            // version 1 with controller/action
            $controller = isset($params['controller']) ? $params['controller'] : null;
            if (!$controller) return 'controllerMissing';
            $action = isset($params['action']) ? $params['action'] : null;
            if (!$action) return 'actionMissing';
            
            $valueToHash = strtolower($controller) . PHP_EOL . strtolower($action);
            if ($debugMode) {
                echo str_pad($this->debugPrefix, 14) . " | " . 
                     str_pad("Controller/Action", $this->debugPadding) . " | " . 
                     $controller . '/' . $action . PHP_EOL;
            }
        }

        if ($version >= 5 && $identifier) {
            $valueToHash .= PHP_EOL . $identifier;
        }

        $valueToHash .= PHP_EOL . $ts . (empty($payload) ? '' : PHP_EOL . json_encode($payload));
        $hash = hash_hmac('sha256', $valueToHash, $accessSecret);

        if ($debugMode) {
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Payload to hash", $this->debugPadding) . " | " . 
                 preg_replace("/\n/", "/", $valueToHash) . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Payload length", $this->debugPadding) . " | " . 
                 strlen($valueToHash) . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("TS type", $this->debugPadding) . " | " . 
                 gettype($ts) . " " . $ts . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Calculated hash", $this->debugPadding) . " | " . 
                 $hash . PHP_EOL;
            echo str_repeat('-', 80) . PHP_EOL;
        }

        return [
            'hash' => $hash,
            'timestamp' => $ts
        ];
    }

    /**
     * Check signed payload
     */
    public function checkSignedPayload($params, $options)
    {
        if (!$options) throw new Exception('optionsRequired');
        
        $path = isset($options['path']) ? $options['path'] : null;
        $headers = isset($options['headers']) ? $options['headers'] : [];
        $method = $options['method'];
        $controller = strtolower(isset($options['controller']) ? $options['controller'] : '');
        $action = strtolower(isset($options['action']) ? $options['action'] : '');
        $accessSecret = $options['accessSecret'];
        $deviation = isset($options['deviation']) ? $options['deviation'] : 10;

        // determine by headers
        $hash = isset($options['hash']) ? $options['hash'] : (isset($headers['x-admiralcloud-hash']) ? $headers['x-admiralcloud-hash'] : null);
        $accessKey = isset($options['accessKey']) ? $options['accessKey'] : (isset($headers['x-admiralcloud-accesskey']) ? $headers['x-admiralcloud-accesskey'] : null);
        $ts = (int)(isset($options['rts']) ? $options['rts'] : (isset($headers['x-admiralcloud-rts']) ? $headers['x-admiralcloud-rts'] : 0));
        $identifier = isset($options['identifier']) ? $options['identifier'] : (isset($headers['x-admiralcloud-identifier']) ? $headers['x-admiralcloud-identifier'] : null);
        $version = (int)(isset($options['version']) ? $options['version'] : (isset($headers['x-admiralcloud-version']) ? $headers['x-admiralcloud-version'] : ($path ? 2 : 1)));
        
        $debugSignature = isset($options['debugSignature']) ? $options['debugSignature'] : (isset($headers['x-admiralcloud-debugsignature']) ? $headers['x-admiralcloud-debugsignature'] : null);
        $errorPrefix = isset($options['errorPrefix']) ? $options['errorPrefix'] : 'acsignature';

        if (!$hash) {
            return ['message' => $errorPrefix . '_hashMissing', 'status' => 401];
        }

        if ($deviation) {
            $min = time() - $deviation;
            $max = time() + $deviation;
            if ($ts < $min || $ts > $max) {
                return [
                    'message' => $errorPrefix . '_rtsDeviation',
                    'status' => 401,
                    'additionalInfo' => ['ts' => $ts, 'deviation' => $deviation]
                ];
            }
        }

        // GET request send parameters as string instead of integer -> parse that here
        if ($method === 'GET') {
            foreach ($params as $key => $value) {
                if ((string)(int)$value === (string)$value) {
                    $params[$key] = (int)$value;
                }
            }
        }

        $payload = [];
        if ($version < 3) {
            $keys = array_keys($params);
            sort($keys);
            foreach ($keys as $key) {
                $payload[$key] = $params[$key];
            }
        } else {
            $payload = $this->deepSortObjectKeys($params);
        }

        $valueToHash = $controller . PHP_EOL . $action;
        if ($version >= 2 && $path) {
            $valueToHash = strtolower($path);
        }
        if ($version >= 5 && $identifier) {
            $valueToHash .= PHP_EOL . $identifier;
        }

        $valueToHash .= PHP_EOL . $ts . (empty($payload) ? '' : PHP_EOL . json_encode($payload));
        $calculatedHash = hash_hmac('sha256', $valueToHash, $accessSecret);

        if ($debugSignature || $calculatedHash !== $hash) {
            echo str_pad("Check Signature V{$version}", 80, '-') . PHP_EOL;
            if ($accessKey) {
                echo str_pad($this->debugPrefix, 14) . " | " . 
                     str_pad("API Key", $this->debugPadding) . " | " . 
                     $accessKey . PHP_EOL;
            }
            if ($version === 2) {
                echo str_pad($this->debugPrefix, 14) . " | " . 
                     str_pad("Path", $this->debugPadding) . " | " . 
                     $path . PHP_EOL;
            } else {
                echo str_pad($this->debugPrefix, 14) . " | " . 
                     str_pad("Controller/Action", $this->debugPadding) . " | " . 
                     $controller . '/' . $action . PHP_EOL;
            }
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Payload to hash", $this->debugPadding) . " | " . 
                 preg_replace("/\n/", "/", $valueToHash) . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Payload length", $this->debugPadding) . " | " . 
                 strlen($valueToHash) . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("TS type", $this->debugPadding) . " | " . 
                 gettype($ts) . " " . $ts . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Expected hash", $this->debugPadding) . " | " . 
                 $calculatedHash . PHP_EOL;
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Sent hash", $this->debugPadding) . " | " . 
                 $hash . PHP_EOL;
            
            $result = "\e[32m✔\e[0m OK"; // OK
            if ($calculatedHash !== $hash) {
                $result = "\e[31m❌\e[0m FAILED";
            }
            echo str_pad($this->debugPrefix, 14) . " | " . 
                 str_pad("Result", $this->debugPadding) . " | " . 
                 $result . PHP_EOL;
            echo str_repeat('-', 80) . PHP_EOL;
        }

        if ($calculatedHash !== $hash) {
            return ['message' => $errorPrefix . '_hashMismatch', 'status' => 401];
        }

        return null;
    }

    /**
     * Deep sort object keys
     */
    private function deepSortObjectKeys($obj)
    {
        if (is_array($obj)) {
            if ($this->isAssoc($obj)) {
                $sorted = [];
                $keys = array_keys($obj);
                sort($keys);
                foreach ($keys as $key) {
                    $sorted[$key] = $this->deepSortObjectKeys($obj[$key]);
                }
                return $sorted;
            }
            return array_map([$this, 'deepSortObjectKeys'], $obj);
        }
        return $obj;
    }

    /**
     * Check if array is associative
     */
    private function isAssoc(array $arr)
    {
        if (array() === $arr) return false;
        return array_keys($arr) !== range(0, count($arr) - 1);
    }
}