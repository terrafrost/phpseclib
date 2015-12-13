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

    /**
     * @requires PHP 5.6
     */
    public function testDebugInfo()
    {
        $num = new Math_BigInteger(50);
        $str = print_r($num, true);
        $this->assertContains('[value] => 0x32', $str);
        return $str;
    }
}
