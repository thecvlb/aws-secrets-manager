<?php

namespace CVLB\AccessManager;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionException;

class AccessManagerTest extends TestCase
{
    /**
     * @var string
     */
    protected $ip = '8.8.8.8';

    protected function setServerAddr(): void
    {
        $_SERVER['SERVER_ADDR'] = $this->ip;
    }

    protected function unsetServerAddr(): void
    {
        unset($_SERVER['SERVER_ADDR']);
    }

    /**
     * @return \PHPUnit\Framework\MockObject\MockObject
     */
    protected function getMockedAccessManager(): \PHPUnit\Framework\MockObject\MockObject
    {
        return $this->getMockBuilder('CVLB\AccessManager\AccessManager')
            ->setConstructorArgs(['encryptme', $this->loggerConfig()])
            ->getMockForAbstractClass();
    }

    /**
     * @return array
     */
    protected function loggerConfig(): array
    {
        return [
            'application_name' => str_replace(' ', '', 'PHP Unit Test'),
            'cloudwatch_group' => 'aws-cloudtrail-logs-202108171424',
            'retention' => 14,
            'tags' => []
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
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();

        $this->assertTrue($obj->getUseCache());
    }

    public function testGetUseCacheSetFalse()
    {
        $method = self::getMethod('setUseCache');
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();
        $method->invokeArgs($obj, [false]);

        $this->assertFalse($obj->getUseCache());
    }

    public function testEncryptValue()
    {
        $unencryptedString = 'tobeencrypted';
        $method = self::getMethod('encryptValue');
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();
        $encryptedString = $method->invokeArgs($obj, [$unencryptedString]);

        $this->assertIsString($encryptedString);
    }

    public function testDecryptValue()
    {
        $unencryptedString = 'tobeencrypted';
        $methodE = self::getMethod('encryptValue');
        $methodD = self::getMethod('decryptValue');
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();
        $encryptedString = $methodE->invokeArgs($obj, [$unencryptedString]);
        $decryptedString = $methodD->invokeArgs($obj, [$encryptedString]);

        $this->assertEquals($unencryptedString, $decryptedString);
    }

    public function testSetBackoff()
    {
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();

        $this->assertInstanceOf('STS\Backoff\Backoff', $obj->getBackoff());
    }

    public function testGetSecretsManager()
    {
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();

        $this->assertInstanceOf('Aws\SecretsManager\SecretsManagerClient', $obj->getSecretsManager());
    }

    public function testGetKeyFromSecret()
    {
        $key = 'secret';
        $value = 'value';
        $secret = json_encode([$key => $value]);
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();

        $this->assertEquals($value, $obj->getKeyFromSecret($secret, $key));
    }

    public function testGetKeyFromSecretNull()
    {
        $key = 'secret';
        $value = 'value';
        $secret = json_encode([$key => $value]);
        $absentKey = 'missing';
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();

        $this->assertNull($obj->getKeyFromSecret($secret, $absentKey));
    }

    public function testAccess()
    {
        $key = 'secret';
        $value = 'value';
        $secret = [$key => $value];
        $secretJson = json_encode($secret);
        $this->setServerAddr();
        $obj = $this->getMockBuilder('CVLB\AccessManager\AccessManager')
            ->setConstructorArgs(['encryptme', $this->loggerConfig()])
            ->onlyMethods(['fromCache'])
            ->getMockForAbstractClass();

        $obj->expects($this->any())
            ->method("fromCache")
            ->with('mySecret')
            ->willReturn($secretJson);

        $this->assertEquals($secretJson, $obj->access('mySecret'));
    }

    public function testAccessWithKey()
    {
        $key = 'secret';
        $value = 'value';
        $secret = [$key => $value];
        $secretJson = json_encode($secret);
        $this->setServerAddr();
        $obj = $this->getMockBuilder('CVLB\AccessManager\AccessManager')
            ->setConstructorArgs(['encryptme', $this->loggerConfig()])
            ->onlyMethods(['fromCache'])
            ->getMockForAbstractClass();

        $obj->expects($this->any())
            ->method("fromCache")
            ->with('mySecret')
            ->willReturn($secretJson);

        $this->assertEquals($value, $obj->access('mySecret', $key));
    }

    public function testFindInstanceIdFromServerAddr()
    {
        $this->setServerAddr();
        $obj = $this->getMockedAccessManager();

        $this->assertEquals($this->ip, $obj->getInstanceId());
    }

    public function testFindInstanceIdFromHostname()
    {
        $ip = '1.1.1.1';
        $this->unsetServerAddr();
        $obj = $this->getMockBuilder('CVLB\AccessManager\AccessManager')
            ->setConstructorArgs(['encryptme', $this->loggerConfig()])
            ->onlyMethods(['getIpFromShell'])
            ->getMockForAbstractClass();

        // Mock return of getIpFromShell()
        $obj->expects($this->any())
            ->method("getIpFromShell")
            ->willReturn($ip);

        // Invoke setInstanceId() in order to call getIpFromShell()
        $obj->setInstanceId();

        $this->assertEquals($ip, $obj->getInstanceId());
    }
}
