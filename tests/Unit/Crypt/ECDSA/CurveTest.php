<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\ECDSA;

/**
 * @requires PHP 7.0
 */`
class Unit_Crypt_ECDSA_CurveTest extends PhpseclibTestCase
{
    public function testBasePoint()
    {
        ECDSA::useInternalEngine();

echo __DIR__; exit;
/*
        foreach (new \DirectoryIterator(__DIR__ . '/../Curves/') as $file) {
            if ($file->getExtension() != 'php') {
                continue;
            }
            $testName = $file->getBasename('.php');
            $class = 'phpseclib\Crypt\ECDSA\Curves\\' . $testName;
            $reflect = new \ReflectionClass($class);
            if ($reflect->isFinal()) {
                continue;
            }
        }
*/

        ECDSA::useBestEngine();
    }

    /**
     * @depends testCreateParameters
     */
    public function testCreateKey($params)
    {
        extract(DSA::createKey());
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $publickey);

        extract(DSA::createKey($params));
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $publickey);

        extract(DSA::createKey(512, 160));
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $publickey);
    }
}

