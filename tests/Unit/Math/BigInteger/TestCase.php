<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2012 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class Unit_Math_BigInteger_TestCase extends PhpseclibTestCase
{
    /**
     * @group github279
     */
    public function zztestDiffieHellmanKeyAgreement()
    {
        // "Oakley Group 14" 2048-bit modular exponentiation group as used in
        // SSH2 diffie-hellman-group14-sha1
        $prime = $this->getInstance(
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' .
            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' .
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' .
            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' .
            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' .
            '83655D23DCA3AD961C62F356208552BB9ED529077096966D' .
            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' .
            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' .
            '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
            16
        );
        $generator = $this->getInstance(2);

        /*
        Code for generation of $alicePrivate and $bobPrivate.
        $class = static::getStaticClass();
        $one = $this->getInstance(1);
        $max = $one->bitwise_leftShift(512)->subtract($one);
        $alicePrivate = $static::randomRange($one, $max);
        $bobPrivate = $static::randomRange($one, $max);
        var_dump($alicePrivate->toHex(), $bobPrivate->toHex());
        */

        $alicePrivate = $this->getInstance(
            '22606EDA7960458BC9D65F46DD96F114F9A004F0493C1F26' .
            '2139D2C8063B733162E876182CA3BF063AB1A167ABDB7F03' .
            'E0A225A6205660439F6CE46D252069FF',
            16
        );
        $bobPrivate = $this->getInstance(
            '6E3EFA13A96025D63E4B0D88A09B3A46DDFE9DD3BC9D1655' .
            '4898C02B4AC181F0CEB4E818664B12F02C71A07215C400F9' .
            '88352A4779F3E88836F7C3D3B3C739DE',
            16
        );

        $alicePublic = $generator->modPow($alicePrivate, $prime);
        $bobPublic =  $generator->modPow($bobPrivate, $prime);

        $aliceShared = $bobPublic->modPow($alicePrivate, $prime);
        $bobShared = $alicePublic->modPow($bobPrivate, $prime);

        $this->assertTrue(
            $aliceShared->equals($bobShared),
            'Failed asserting that Alice and Bob share the same BigInteger.'
        );
    }

    /**
     * @group github954
     */
    public function testSlidingWindow()
    {
        $e = $this->getInstance(str_repeat('1', 1794), 2);
        $x = $this->getInstance(1);
        $n = $this->getInstance(2);
        $x->powMod($e, $n);
    }
}
