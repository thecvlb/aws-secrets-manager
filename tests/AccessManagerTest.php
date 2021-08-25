<?php

namespace CVLB\AccessManager;

use Aws\Credentials\Credentials;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionException;

class AccessManagerTest extends TestCase
{
    protected function getMockedAccessManager()
    {
        return $this->getMockBuilder('CVLB\AccessManager\AccessManager')
            ->disableOriginalConstructor()
            ->getMockForAbstractClass();
    }

    protected static function makeConfig($credentials = null, $encryption_key = null, $cloudWatchConfig = [], $use_cache = true)
    {
        return  [
            'credentials' => new Credentials('key', 'secret'),
            'encryption_key' => 'mycrypto',
            'cloudWatchConfig' => ['cloudwatch_group'=>null, 'application_name'=>'test', 'retention'=>14, 'tags'=>[]],
            'use_cache' => true
        ];
    }

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

    public function testGetUseCache()
    {
        $obj = $this->getMockedAccessManager();

        $this->assertTrue($obj->getUseCache());
    }

    public function testGetUseCacheSetFalse()
    {
        $method = self::getMethod('setUseCache');
        $obj = $this->getMockedAccessManager();
        $method->invokeArgs($obj, [false]);

        $this->assertFalse($obj->getUseCache());
    }

    public function testEncryptValue()
    {
        $unencryptedString = 'tobeencrypted';
        $method = self::getMethod('encryptValue');
        $obj = $this->getMockedAccessManager();
        $encryptedString = $method->invokeArgs($obj, [$unencryptedString]);

        $this->assertIsString($encryptedString);
    }

    public function testDecryptValue()
    {
        $unencryptedString = 'tobeencrypted';
        $methodE = self::getMethod('encryptValue');
        $methodD = self::getMethod('decryptValue');
        $obj = $this->getMockedAccessManager();
        $encryptedString = $methodE->invokeArgs($obj, [$unencryptedString]);
        $decryptedString = $methodD->invokeArgs($obj, [$encryptedString]);

        $this->assertEquals($unencryptedString, $decryptedString);
    }
}
