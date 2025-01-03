<?php

/**
 * DNSSEC (RFC4034) Key Handler
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\DH\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\DNSSEC as Progenitor;
use phpseclib3\Crypt\DH;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;

/**
 * DNSSEC (RFC4034) Formatted DH Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class DNSSEC extends Progenitor
{
    /**
     * Break a public or private key down into its constituent components
     *
     * @param string $key
     * @param string $password optional
     * @return array
     */
    public static function load($key, $password = '')
    {
        $key = parent::load($key, $password);

        if ($key['Algorithm'] != 2) {
            throw new UnsupportedAlgorithmException(self::algorithmID2Name($new['Algorithm']) . ' is not supported by this class');
        }

        if (isset($key['Private-key-format'])) {
            $indices = ['Prime(p)', 'Generator(g)', 'Private_value(x)', 'Public_value(y)'];
            foreach ($indices as $index) {
                if (!isset($key[$index])) {
                    throw new \RuntimeException("Key doesn't contain value for $index");
                }
                if (!preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $key[$index])) {
                    throw new \RuntimeException("$index does not appear to be base64-encoded");
                }
                $key[$index] = new BigInteger(Strings::base64_decode($key[$index]), 256);
            }
            return [
                'privateKey' => $key['Private_value(x)'],
                'publicKey' => $key['Public_value(y)'],
                'prime' => $key['Prime(p)'],
                'base' => $key['Generator(g)']
            ];
        }

        // https://www.rfc-editor.org/rfc/rfc2539.html#section-2 talks about the format of public keys

        // Prime length is length of the Diffie-Hellman prime (p) in bytes if it is 16 or greater.
        list(, $length) = unpack('n', Strings::shift($key['Key'], 2));
        if ($length == 0 || ($length >= 3 && $length <= 15)) {
            throw new \RuntimeException('Assignment of meaning to Prime Lengths of 0 and 3 through 15 requires an IETF consensus.');
        }
        // If "prime length" field is 1 or 2, then the "prime" field is actually an unsigned index into a table of 65,536
        // prime/generator pairs and the generator length SHOULD be zero.
        if ($length <= 2) {
            $idx = ord(Strings::shift($key['Key']));
            $prime = DH::getPrimeFromGroupNo($idx);
            Strings::shift($key['Key'], 2);
            $base = new BigInteger(2);
        } else {
            $prime = new BigInteger(Strings::shift($key['Key'], $length), 256);
            list(, $length) = unpack('n', Strings::shift($key['Key'], 2));
            $base = new BigInteger(Strings::shift($key['Key'], $length), 256);
        }
        list(, $length) = unpack('n', Strings::shift($key['Key'], 2));
        $publicKey = new BigInteger(Strings::shift($key['Key'], $length), 256);
        return [
            'publicKey' => $publicKey,
            'prime' => $prime,
            'base' => $base
        ];
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @param BigInteger $prime
     * @param BigInteger $base
     * @param BigInteger $privateKey
     * @param BigInteger $publicKey
     * @param string $password optional
     * @param array $options optional
     * @return string
     */
    public static function savePrivateKey(BigInteger $prime, BigInteger $base, BigInteger $privateKey, BigInteger $publicKey, $password = '', array $options = [])
    {
        return self::wrapPrivateKey([
            'Algorithm' => '2 (DH)',
            'Prime(p)' => Strings::base64_encode($prime->toBytes()),
            'Generator(g)' => Strings::base64_encode($base->toBytes()),
            'Private_value(x)' => Strings::base64_encode($privateKey->toBytes()),
            'Public_value(y)' => Strings::base64_encode($publicKey->toBytes())
        ]);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @param BigInteger $prime
     * @param BigInteger $base
     * @param BigInteger $publicKey
     * @param array $options optional
     * @return string
     */
    public static function savePublicKey(BigInteger $prime, BigInteger $base, BigInteger $publicKey, array $options = [])
    {
        $prime = $prime->toBytes();
        $base = $base->toBytes();
        $publicKey = $publicKey->toBytes();
        $data = pack('na*na*na*', strlen($prime), $prime, strlen($base), $base, strlen($publicKey), $publicKey);
        return '2 ' . Strings::base64_encode($data);
    }
}