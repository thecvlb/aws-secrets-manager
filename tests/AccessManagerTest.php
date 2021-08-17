<?php

namespace CVLB\AccessManager;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionException;

class AccessManagerTest extends TestCase
{
    /**
     * @var array
     */
    public $config = [
        'aws_key' => 'key',
        'aws_secret' => 'secret',
        'encryption_key' => 'crypt',
        'use_cache' => true
    ];

    /**
     * @param $name
     * @return ReflectionMethod
     * @throws ReflectionException
     */
    protected static function getMethod($name): ReflectionMethod
    {
        $class = new ReflectionClass('CVLB\AccessManager\AccessManager');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

    public function test__construct()
    {
        $obj = $this->getMockForAbstractClass(AccessManager::class, ['config' => $this->config]);

        $this->assertInstanceOf('CVLB\AccessManager\AccessManager', $obj);
    }

    public function testGetUseCache()
    {
        $obj = $this->getMockForAbstractClass(AccessManager::class, ['config' => $this->config]);

        $this->assertTrue($obj->getUseCache());
    }

    public function testGetUseCacheSetFalse()
    {
        // Set to false
        $this->config['use_cache'] = false;

        $obj = $this->getMockForAbstractClass(AccessManager::class, ['config' => $this->config]);

        $this->assertFalse($obj->getUseCache());
    }

    public function testGetUseCacheDefaultValue()
    {
        // Unset key to force default value
        unset($this->config['use_cache']);

        $obj = $this->getMockForAbstractClass(AccessManager::class, ['config' => $this->config]);

        $this->assertTrue($obj->getUseCache());
    }

    public function testEncryptValue()
    {
        $unencryptedString = 'tobeencrypted';
        $method = self::getMethod('encryptValue');
        $obj = $this->getMockForAbstractClass(AccessManager::class, ['config' => $this->config]);
        $encryptedString = $method->invokeArgs($obj, [$unencryptedString]);

        $this->assertIsString($encryptedString);
    }

    public function testDecryptValue()
    {
        $unencryptedString = 'tobeencrypted';
        $methodE = self::getMethod('encryptValue');
        $methodD = self::getMethod('decryptValue');
        $obj = $this->getMockForAbstractClass(AccessManager::class, ['config' => $this->config]);
        $encryptedString = $methodE->invokeArgs($obj, [$unencryptedString]);
        $decryptedString = $methodD->invokeArgs($obj, [$encryptedString]);

        $this->assertEquals($unencryptedString, $decryptedString);
    }
}
