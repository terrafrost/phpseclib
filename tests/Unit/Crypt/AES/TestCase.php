<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Crypt\AES;

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Rijndael;
use phpseclib3\Exception\InconsistentSetupException;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Tests\PhpseclibTestCase;

abstract class TestCase extends PhpseclibTestCase
{
    protected $engine;

    private function _checkEngine($aes)
    {
        if ($aes->getEngine() != $this->engine) {
            self::markTestSkipped('Unable to initialize ' . $this->engine . ' engine');
        }
    }

    /**
     * Produces all combinations of test values.
     */
    public static function continuousBufferCombos(): array
    {
        $modes = [
            'ctr',
            'ofb',
            'cfb',
            'cfb8',
            'ofb8',
        ];
        $plaintexts = [
            '',
            '12345678901234567', // https://github.com/phpseclib/phpseclib/issues/39
            "\xDE\xAD\xBE\xAF",
            ':-):-):-):-):-):-)', // https://github.com/phpseclib/phpseclib/pull/43
        ];
        $ivs = [
            str_repeat("\0", 16),
            str_pad('test123', 16, "\0"),
        ];
        $keys = [
            str_repeat("\0", 16),
            str_pad(':-8', 16, "\0"), // https://github.com/phpseclib/phpseclib/pull/43
            str_pad('FOOBARZ', 16, "\0"),
        ];

        $result = [];

        foreach ($modes as $mode) {
            foreach ($plaintexts as $plaintext) {
                foreach ($ivs as $iv) {
                    foreach ($keys as $key) {
                        $result[] = [$mode, $plaintext, $iv, $key];
                    }
                }
            }
        }

        return $result;
    }

    /**
     * @dataProvider continuousBufferCombos
     */
    public function testEncryptDecryptWithContinuousBuffer($mode = '', $plaintext = '', $iv = '', $key = ''): void
    {
        if (!strlen($mode)) {
            $this->assertTrue(true);
        }
        var_dump(func_get_args());
        exit;
        $aes = new AES($mode);
        $aes->setPreferredEngine($this->engine);
        $aes->enableContinuousBuffer();
        $aes->setIV($iv);
        $aes->setKey($key);

        $this->_checkEngine($aes);

        $actual = '';
        for ($i = 0, $strlen = strlen($plaintext); $i < $strlen; ++$i) {
            $actual .= $aes->decrypt($aes->encrypt($plaintext[$i]));
        }

        $this->assertEquals($plaintext, $actual);
    }
}
