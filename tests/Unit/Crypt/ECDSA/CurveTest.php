<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\ECDSA;

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
}

