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
    public function engineVectors()
    {
        $engines = [
            'PHP',
            'Eval',
        ];

        // tests from https://www.schneier.com/code/vectors.txt
        $tests = [
            // key, plaintext, ciphertext
            [pack('H*', '0000000000000000'), pack('H*', '0000000000000000'), pack('H*', '4EF997456198DD78')],
            [pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', '51866FD5B85ECB8A')],
            [pack('H*', '3000000000000000'), pack('H*', '1000000000000001'), pack('H*', '7D856F9A613063F2')],
            [pack('H*', '1111111111111111'), pack('H*', '1111111111111111'), pack('H*', '2466DD878B963C9D')],
            [pack('H*', '0123456789ABCDEF'), pack('H*', '1111111111111111'), pack('H*', '61F9C3802281B096')],
            [pack('H*', '1111111111111111'), pack('H*', '0123456789ABCDEF'), pack('H*', '7D0CC630AFDA1EC7')],
            [pack('H*', '0000000000000000'), pack('H*', '0000000000000000'), pack('H*', '4EF997456198DD78')],
            [pack('H*', 'FEDCBA9876543210'), pack('H*', '0123456789ABCDEF'), pack('H*', '0ACEAB0FC6A0A28D')],
            [pack('H*', '7CA110454A1A6E57'), pack('H*', '01A1D6D039776742'), pack('H*', '59C68245EB05282B')],
            [pack('H*', '0131D9619DC1376E'), pack('H*', '5CD54CA83DEF57DA'), pack('H*', 'B1B8CC0B250F09A0')],
            [pack('H*', '07A1133E4A0B2686'), pack('H*', '0248D43806F67172'), pack('H*', '1730E5778BEA1DA4')],
            [pack('H*', '3849674C2602319E'), pack('H*', '51454B582DDF440A'), pack('H*', 'A25E7856CF2651EB')],
            [pack('H*', '04B915BA43FEB5B6'), pack('H*', '42FD443059577FA2'), pack('H*', '353882B109CE8F1A')],
            [pack('H*', '0113B970FD34F2CE'), pack('H*', '059B5E0851CF143A'), pack('H*', '48F4D0884C379918')],
            [pack('H*', '0170F175468FB5E6'), pack('H*', '0756D8E0774761D2'), pack('H*', '432193B78951FC98')],
            [pack('H*', '43297FAD38E373FE'), pack('H*', '762514B829BF486A'), pack('H*', '13F04154D69D1AE5')],
            [pack('H*', '07A7137045DA2A16'), pack('H*', '3BDD119049372802'), pack('H*', '2EEDDA93FFD39C79')]
        ];

        $result = [];

        foreach ($engines as $engine) {
            foreach ($tests as $test) {
                $result[] = [$engine, $test[0], $test[1], $test[2]];
            }
        }

        return $result;
    }

    /**
     * @dataProvider engineVectors
     */
    public function testVectors($engine, $key, $plaintext, $expected)
    {
        $bf = new Blowfish('cbc');
        $bf->setKey($key);
        $bf->setIV(str_repeat("\0", $bf->getBlockLength() >> 3));

        if (!$bf->isValidEngine($engine)) {
            self::markTestSkipped("Unable to initialize $engine engine");
        }
        $bf->setPreferredEngine($engine);
        $bf->disablePadding();
        $result = $bf->encrypt($plaintext);
        $plaintext = bin2hex($plaintext);
        $this->assertEquals($result, $expected, "Failed asserting that $plaintext yielded expected output in $engine engine");
    }

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
                $objects[$i]->setKey($key);
                $this->assertEquals($ref, 
$objects[$i]
->encrypt($plaintext), 
"Failed asserting that {$engines[$i]} yields the same output as the internal engine with a key size of $keyLen (" . bin2hex($key) . ')');
            }
        }
    }
}
