<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2012 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Math/BigInteger.php';

abstract class Unit_Math_BigInteger_TestCase extends PhpseclibTestCase
{
    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::reRequireFile('Math/BigInteger.php');
    }

    public function getInstance($x = 0, $base = 10)
    {
        return new Math_BigInteger($x, $base);
    }

    public function testConstructorBase2()
    {
        // 2**65 = 36893488147419103232
        $this->assertSame('36893488147419103232', (string) $this->getInstance('1' . str_repeat('0', 65), 2));
    }

    public function testZeroBase10()
    {
        $temp = $this->getInstance('0');
        $this->assertSame($temp->toString(), '0');
    }
}
