<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Blowfish;
use phpseclib\Crypt\Random;

class Unit_Crypt_BlowfishTest extends PhpseclibTestCase
{
    public function testKeySizes()
    {
        $objects = $engines = [];
        $temp = new Blowfish('ctr');
        $temp->setPreferredEngine('PHP');
        $objects[] = $temp;
        $engines[] = 'internal';

        if ($temp->isValidEngine('mcrypt')) {
            $temp = new Blowfish('ctr');
            $temp->setPreferredEngine('mcrypt');
            $objects[] = $temp;
            $engines[] = 'mcrypt';
        }

        if ($temp->isValidEngine('OpenSSL')) {
            $temp = new Blowfish('ctr');
            $temp->setPreferredEngine('OpenSSL');
            $objects[] = $temp;
            $engines[] = 'OpenSSL';
        }

        if (count($objects) < 2) {
            self::markTestSkipped('Unable to initialize two or more engines');
        }

        for ($i = 0; $i < count($objects); $i++) {
            $objects[$i]->setIV(str_repeat('x', $objects[$i]->getBlockLength() >> 3));
        }

        $plaintext = str_repeat('.', 100);

        for ($keyLen = 4; $keyLen <= 56; $keyLen++) {
            $key = Random::string($keyLen);
            $objects[0]->setKey($key);
            $ref = $objects[0]->encrypt($plaintext);
            for ($i = 1; $i < count($objects); $i++) {
echo $objcts[$i]->getEngine() . " with keylen of $keylen\n";
                $objects[$i]->setKey($key);
                $this->assertEquals($ref, $objects[$i]->encrypt($plaintext), "Failed asserting that {$engines[$i]} yields the same output as the internal engine with a key size of $keyLen");
            }
        }
    }
}
