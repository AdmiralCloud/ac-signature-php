<?php

use PHPUnit\Framework\TestCase;

class acSignatureTest extends TestCase
{
    private $acSignature;
    private $accessSecret = 'test-secret';
    private $testPayload;
    private $timestamp;

    protected function setUp(): void
    {
        $this->acSignature = new acSignature();
        $this->timestamp = time();
        $this->testPayload = [
            'test' => 'value',
            'nested' => [
                'inner' => 'value',
                'array' => ['c', 'b', 'a']
            ]
        ];
    }

    public function testSignV1()
    {
        $params = [
            'accessSecret' => $this->accessSecret,
            'controller' => 'test',
            'action' => 'action',
            'payload' => $this->testPayload,
            'ts' => $this->timestamp
        ];

        $result = $this->acSignature->sign($params);
        
        $this->assertArrayHasKey('hash', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertEquals($this->timestamp, $result['timestamp']);
    }

    public function testSignV2()
    {
        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => '/api/test',
            'payload' => $this->testPayload,
            'ts' => $this->timestamp
        ];

        $result = $this->acSignature->sign2($params);
        
        $this->assertArrayHasKey('hash', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertEquals($this->timestamp, $result['timestamp']);
    }

    public function testSignV5()
    {
        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => '/api/test',
            'identifier' => 'test-user',
            'payload' => $this->testPayload,
            'ts' => $this->timestamp
        ];

        $result = $this->acSignature->sign5($params);
        
        $this->assertArrayHasKey('hash', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertEquals($this->timestamp, $result['timestamp']);
    }

    public function testCheckSignedPayload()
    {
        // First create a signature
        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => '/api/test',
            'payload' => $this->testPayload,
            'ts' => $this->timestamp
        ];

        $signature = $this->acSignature->sign2($params);

        // Then verify it
        $options = [
            'path' => '/api/test',
            'method' => 'POST',
            'accessSecret' => $this->accessSecret,
            'headers' => [
                'x-admiralcloud-hash' => $signature['hash'],
                'x-admiralcloud-rts' => $signature['timestamp'],
                'x-admiralcloud-version' => 2
            ]
        ];

        $result = $this->acSignature->checkSignedPayload($this->testPayload, $options);
        
        $this->assertNull($result, 'Signature verification should pass');
    }

    public function testSignatureWithIdentifier()
    {
        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => '/api/test',
            'identifier' => 'test-user',
            'payload' => $this->testPayload,
            'ts' => $this->timestamp
        ];

        $signature = $this->acSignature->sign5($params);

        $options = [
            'path' => '/api/test',
            'method' => 'POST',
            'accessSecret' => $this->accessSecret,
            'headers' => [
                'x-admiralcloud-hash' => $signature['hash'],
                'x-admiralcloud-rts' => $signature['timestamp'],
                'x-admiralcloud-version' => 5,
                'x-admiralcloud-identifier' => 'test-user'
            ]
        ];

        $result = $this->acSignature->checkSignedPayload($this->testPayload, $options);
        
        $this->assertNull($result, 'Signature verification with identifier should pass');
    }

    public function testInvalidHash()
    {
        $options = [
            'path' => '/api/test',
            'method' => 'POST',
            'accessSecret' => $this->accessSecret,
            'headers' => [
                'x-admiralcloud-hash' => 'invalid-hash',
                'x-admiralcloud-rts' => time(),
                'x-admiralcloud-version' => 2
            ]
        ];

        $result = $this->acSignature->checkSignedPayload($this->testPayload, $options);
        
        $this->assertIsArray($result);
        $this->assertEquals('acsignature_hashMismatch', $result['message']);
        $this->assertEquals(401, $result['status']);
    }
}