<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\RSA;

class Unit_Crypt_RSA_CreateKeyTest extends PhpseclibTestCase
{
    static protected $privatekey;
    static protected $publickey;

    public function testCreateKey()
    {
        var_dump(RSA::createKey(512)); exit;
var_dump($privatekey);
exit;
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $publickey);
        $this->assertNotEmpty("$privatekey");
        $this->assertNotEmpty("$publickey");

        self::$publickey = $publickey;
        self::$privatekey = $privatekey;
    }

    /**
     * @depends testCreateKey
     */
    public function testEncryptDecrypt()
    {
        $ciphertext = self::$publickey->encrypt('zzz');
        $this->assertInternalType('string', $ciphertext);
        $plaintext = self::$publickey->decrypt($ciphertext);
        $this->assertSame($plaintext, 'zzz');
    }
}
