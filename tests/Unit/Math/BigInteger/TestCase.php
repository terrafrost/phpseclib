<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2012 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class Unit_Math_BigInteger_TestCase extends PhpseclibTestCase
{
    public function testRandomPrime()
    {
        $class = static::getStaticClass();
        $prime = $class::randomPrime(128);
        $this->assertSame(128, $prime->getLength());
    }
}
