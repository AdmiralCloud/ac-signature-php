<?php

use PHPUnit\Framework\TestCase;

class acSignatureV5Test extends TestCase
{
    private $acSignature;
    private $accessSecret = 'test-secret';
    private $timestamp;
    private $basePath = '/api/test';
    private $baseIdentifier = 'test-user';

    protected function setUp(): void
    {
        $this->acSignature = new acSignature();
        $this->timestamp = time();
    }

    /**
     * Test komplexe verschachtelte Payloads
     */
    public function testComplexNestedPayload()
    {
        $complexPayload = [
            'nested' => [
                'deeply' => [
                    'array' => [3, 1, 2],
                    'object' => [
                        'c' => 'value',
                        'a' => 'value',
                        'b' => 'value'
                    ]
                ],
                'mixed' => [
                    null,
                    123,
                    'string',
                    ['nested', 'array'],
                    (object)['key' => 'value']
                ]
            ],
            'simple' => 'value'
        ];

        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => $this->basePath,
            'identifier' => $this->baseIdentifier,
            'payload' => $complexPayload,
            'ts' => $this->timestamp
        ];

        $signature = $this->acSignature->sign5($params);
        
        $options = [
            'path' => $this->basePath,
            'method' => 'POST',
            'accessSecret' => $this->accessSecret,
            'headers' => [
                'x-admiralcloud-hash' => $signature['hash'],
                'x-admiralcloud-rts' => $signature['timestamp'],
                'x-admiralcloud-version' => 5,
                'x-admiralcloud-identifier' => $this->baseIdentifier
            ]
        ];

        $result = $this->acSignature->checkSignedPayload($complexPayload, $options);
        $this->assertNull($result, 'Complex nested payload should be handled correctly');
    }

    /**
     * Test Sonderzeichen im Path
     */
    public function testSpecialCharactersInPath()
    {
        $specialPaths = [
            '/api/test/with space',
            '/api/test/with%20encoding',
            '/api/test/with+plus',
            '/api/test/with&special=param',
            '/api/test/with#fragment',
            // Entfernt: '/api/test/with?query=param', // Query-Parameter werden nicht unterstützt
            '/api/test/with/ümlaut/ß/é'
        ];

        foreach ($specialPaths as $path) {
            $params = [
                'accessSecret' => $this->accessSecret,
                'path' => $path,
                'identifier' => $this->baseIdentifier,
                'payload' => ['test' => 'value'],
                'ts' => $this->timestamp
            ];

            $signature = $this->acSignature->sign5($params);
            
            $options = [
                'path' => $path,
                'method' => 'POST',
                'accessSecret' => $this->accessSecret,
                'headers' => [
                    'x-admiralcloud-hash' => $signature['hash'],
                    'x-admiralcloud-rts' => $signature['timestamp'],
                    'x-admiralcloud-version' => 5,
                    'x-admiralcloud-identifier' => $this->baseIdentifier
                ]
            ];

            $result = $this->acSignature->checkSignedPayload(['test' => 'value'], $options);
            $this->assertNull($result, "Path '$path' should be handled correctly");
        }
    }

    /**
     * Test Sonderzeichen im Identifier
     */
    public function testSpecialCharactersInIdentifier()
    {
        $specialIdentifiers = [
            'user@example.com',
            'user+alias@example.com',
            'user with spaces',
            'user/with/slashes',
            'user_with_underscores',
            'user-with-dashes',
            'üser.with.special.chars'
        ];

        foreach ($specialIdentifiers as $identifier) {
            $params = [
                'accessSecret' => $this->accessSecret,
                'path' => $this->basePath,
                'identifier' => $identifier,
                'payload' => ['test' => 'value'],
                'ts' => $this->timestamp
            ];

            $signature = $this->acSignature->sign5($params);
            
            $options = [
                'path' => $this->basePath,
                'method' => 'POST',
                'accessSecret' => $this->accessSecret,
                'headers' => [
                    'x-admiralcloud-hash' => $signature['hash'],
                    'x-admiralcloud-rts' => $signature['timestamp'],
                    'x-admiralcloud-version' => 5,
                    'x-admiralcloud-identifier' => $identifier
                ]
            ];

            $result = $this->acSignature->checkSignedPayload(['test' => 'value'], $options);
            $this->assertNull($result, "Identifier '$identifier' should be handled correctly");
        }
    }

    /**
     * Test Zeitabweichungen
     */
    public function testTimestampDeviation()
    {
        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => $this->basePath,
            'identifier' => $this->baseIdentifier,
            'payload' => ['test' => 'value'],
            'ts' => $this->timestamp
        ];

        $signature = $this->acSignature->sign5($params);

        // Test verschiedene Abweichungen
        $deviations = [5, 10, 15, 30];
        foreach ($deviations as $deviation) {
            $options = [
                'path' => $this->basePath,
                'method' => 'POST',
                'accessSecret' => $this->accessSecret,
                'deviation' => $deviation,
                'headers' => [
                    'x-admiralcloud-hash' => $signature['hash'],
                    'x-admiralcloud-rts' => $this->timestamp,
                    'x-admiralcloud-version' => 5,
                    'x-admiralcloud-identifier' => $this->baseIdentifier
                ]
            ];

            // Test innerhalb der Abweichung
            $result = $this->acSignature->checkSignedPayload(['test' => 'value'], $options);
            $this->assertNull($result, "Should accept timestamp within $deviation seconds deviation");

            // Test außerhalb der Abweichung
            $options['headers']['x-admiralcloud-rts'] = $this->timestamp - ($deviation + 1);
            $result = $this->acSignature->checkSignedPayload(['test' => 'value'], $options);
            $this->assertArrayHasKey('message', $result);
            $this->assertEquals('acsignature_rtsDeviation', $result['message']);
        }
    }

    /**
     * Test Empty Edge Cases
     */
    public function testEdgeCases()
    {
        $edgeCases = [
            // Leerer JSON Payload
            [
                'name' => 'Empty JSON object',
                'payload' => [],
                'shouldPass' => true
            ],
            // Minimaler JSON Payload
            [
                'name' => 'Minimal JSON object',
                'payload' => ['key' => null],
                'shouldPass' => true
            ],
            // Leerer Path (sollte fehlschlagen)
            [
                'name' => 'Empty path',
                'path' => '',
                'payload' => [],
                'shouldPass' => false
            ],
            // Leerer Identifier (sollte funktionieren)
            [
                'name' => 'Empty identifier',
                'identifier' => '',
                'payload' => [],
                'shouldPass' => true
            ],
            // Nur Forward Slash Path
            [
                'name' => 'Root path',
                'path' => '/',
                'payload' => [],
                'shouldPass' => true
            ],
            // JSON Payload mit verschiedenen leeren Strukturen
            [
                'name' => 'JSON with empty structures',
                'payload' => [
                    'emptyArray' => [],
                    'emptyObject' => new stdClass(),
                    'nullValue' => null
                ],
                'shouldPass' => true
            ]
        ];

        foreach ($edgeCases as $case) {
            $params = [
                'accessSecret' => $this->accessSecret,
                'path' => isset($case['path']) ? $case['path'] : $this->basePath,
                'identifier' => isset($case['identifier']) ? $case['identifier'] : $this->baseIdentifier,
                'payload' => $case['payload'],  // Jetzt immer gesetzt mit mindestens []
                'ts' => $this->timestamp
            ];

            try {
                $signature = $this->acSignature->sign5($params);
                
                if ($case['shouldPass']) {
                    $this->assertArrayHasKey('hash', $signature, $case['name'] . ' should generate valid signature');
                    
                    $options = [
                        'path' => isset($case['path']) ? $case['path'] : $this->basePath,
                        'method' => 'POST',
                        'accessSecret' => $this->accessSecret,
                        'headers' => [
                            'x-admiralcloud-hash' => $signature['hash'],
                            'x-admiralcloud-rts' => $signature['timestamp'],
                            'x-admiralcloud-version' => 5,
                            'x-admiralcloud-identifier' => isset($case['identifier']) ? $case['identifier'] : $this->baseIdentifier
                        ]
                    ];

                    $result = $this->acSignature->checkSignedPayload($case['payload'], $options);
                    $this->assertNull($result, $case['name'] . ' should pass validation');
                }
            } catch (Exception $e) {
                if ($case['shouldPass']) {
                    $this->fail($case['name'] . ' should not throw exception: ' . $e->getMessage());
                } else {
                    // Wenn der Test fehlschlagen soll, ist eine Exception okay
                    $this->assertTrue(true, $case['name'] . ' failed as expected');
                }
            }
        }
    }

    /**
     * Test große Payloads
     */
    public function testLargePayload()
    {
        $largePayload = [];
        // Erstelle einen großen verschachtelten Payload
        for ($i = 0; $i < 100; $i++) {
            $largePayload["key$i"] = [
                'nested' => [
                    'array' => range(0, 50),
                    'string' => str_repeat('long string ', 20),
                    'objects' => array_fill(0, 10, [
                        'a' => 'value',
                        'b' => range(0, 10),
                        'c' => [
                            'deep' => str_repeat('nested ', 10)
                        ]
                    ])
                ]
            ];
        }

        $params = [
            'accessSecret' => $this->accessSecret,
            'path' => $this->basePath,
            'identifier' => $this->baseIdentifier,
            'payload' => $largePayload,
            'ts' => $this->timestamp
        ];

        $signature = $this->acSignature->sign5($params);
        
        $options = [
            'path' => $this->basePath,
            'method' => 'POST',
            'accessSecret' => $this->accessSecret,
            'headers' => [
                'x-admiralcloud-hash' => $signature['hash'],
                'x-admiralcloud-rts' => $signature['timestamp'],
                'x-admiralcloud-version' => 5,
                'x-admiralcloud-identifier' => $this->baseIdentifier
            ]
        ];

        $result = $this->acSignature->checkSignedPayload($largePayload, $options);
        $this->assertNull($result, 'Large payload should be handled correctly');
    }
}