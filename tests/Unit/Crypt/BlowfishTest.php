<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Crypt;

use phpseclib3\Crypt\Blowfish;
use phpseclib3\Crypt\Random;
use phpseclib3\Tests\PhpseclibTestCase;

class BlowfishTest extends PhpseclibTestCase
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
echo "keyLen = $keyLen\n";
            $key = Random::string($keyLen);
            $objects[0]->setKey($key);
            $ref = $objects[0]->encrypt($plaintext);
            for ($i = 1; $i < count($objects); $i++) {
echo '   ' . $engines[$i] . "\n";
                $objects[$i]->setKey($key);
                $this->assertEquals($ref, 
$objects[$i]
->encrypt($plaintext), 
"Failed asserting that {$engines[$i]} yields the same output as the internal engine with a key size of $keyLen (" . bin2hex($key) . ')');
            }
        }
    }
}
