<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\TripleDES;

class Unit_Crypt_TripleDESTest extends PhpseclibTestCase
{
    var $engines = [
        'PHP',
        'Eval',
        'mcrypt',
        'OpenSSL',
    ];

    public function testInnerChaining()
    {
        // regular CBC returns
        //           e089b6d84708c6bc80be6c2da82bd19a79ffe11f02933ac1
        $expected = 'e089b6d84708c6bc6f04c8971121603d7be2861efae0f3f5';

        $des = new TripleDES('3cbc');
        $des->setKey('abcdefghijklmnopqrstuvwx');
        $des->setIV(str_repeat("\0", $des->getBlockLength() >> 3));

        foreach ($this->engines as $engine) {
echo "engine = $engine\n";
            $des->setPreferredEngine($engine);
            if (!$des->isValidEngine($engine)) {
                self::markTestSkipped("Unable to initialize $engine engine");
            }
            $result = bin2hex($des->encrypt(str_repeat('a', 16)));
            $this->assertEquals($result, $expected, "Failed asserting inner chainin worked correctly in $engine engine");
        }
    }
}
