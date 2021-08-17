<?php

namespace CVLB\AccessManager;

use PHPUnit\Framework\TestCase;

class AccessManagerTest extends TestCase
{

    public function test__construct()
    {
        $config = [
            'aws_key' => 'key',
            'aws_secret' => 'secret',
            'encryption_key' => 'crypt'
        ];
        $stub = $this->getMockForAbstractClass(AccessManager::class, ['config' => $config]);

        $this->assertInstanceOf('CVLB\AccessManager\AccessManager', $stub);
    }
}
