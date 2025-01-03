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

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\DNSSEC as Progenitor;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;

/**
 * DNSSEC (RFC4034) Formatted RSA Key Handler
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

        switch ($key['Algorithm']) {
            case 1:
                $hash = 'md5';
                break;
            case 5:
                $hash = 'sha1';
                break;
            case 8:
                $hash = 'sha256';
                break;
            case 10:
                $hash = 'sha512';
                break;
            default:
                throw new UnsupportedAlgorithmException(self::algorithmID2Name($key['Algorithm']) . ' is not supported by this class');
        }

        if (isset($key['Private-key-format'])) {
            $indices = ['Modulus', 'PublicExponent', 'PrivateExponent', 'Prime1', 'Prime2', 'Exponent1', 'Exponent2', 'Coefficient'];
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
                'modulus' => $key['Modulus'],
                'publicExponent' => $key['PublicExponent'],
                'privateExponent' => $key['PrivateExponent'],
                'primes' => [1 => $key['Prime1'], $key['Prime2']],
                'exponents' => [1 => $key['Exponent1'], $key['Exponent2']],
                'coefficients' => [2 => $key['Coefficient']],
                'hash' => $hash,
                'isPublicKey' => false
            ];
        }

        // https://www.rfc-editor.org/rfc/rfc3110.html#section-2 discusses the format of public keys

        $exponentLength = ord(Strings::shift($key['Key']));
        list(, $altLength) = unpack('n', Strings::shift($key['Key'], 2));
        if (!$exponentLength) {
            $exponentLength = $altLength;
        }

        return [
            'publicExponent' => new BigInteger(Strings::shift($key['Key'], $exponentLength), 256),
            'modulus' => new BigInteger($key['Key'], 256),
            'hash' => $hash,
            'isPublicKey' => true
        ];
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @param BigInteger $n
     * @param BigInteger $e
     * @param BigInteger $d
     * @param array $primes
     * @param array $exponents
     * @param array $coefficients
     * @param string $password optional
     * @param array $options optional
     * @return string
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
    {
        if (count($primes) != 2) {
            throw new \InvalidArgumentException('DNSSEC does not support multi-prime RSA keys');
        }
        if (!isset($options['hash'])) {
            throw new \InvalidArgumentException("DNSSEC keys require the options array have 'hash' as a key");
        }

        switch ($options['hash']) {
            case 'md5':
                $algo = '1 (RSAMD5)';
                break;
            case 'sha1':
                $algo = '5 (RSASHA1)';
                break;
            case 'sha256':
                $algo = '8 (RSASHA256)';
                break;
            case 'sha512':
                $algo = '10 (RSASHA512)';
                break;
            default:
                throw new UnsupportedAlgorithmException($options['hash'] . ' is not supported by this class');
        }

        return self::wrapPrivateKey([
            'Algorithm' => $algo,
            'Modulus' => Strings::base64_encode($n->toBytes()),
            'PublicExponent' => Strings::base64_encode($e->toBytes()),
            'PrivateExponent' => Strings::base64_encode($d->toBytes()),
            'Prime1' => Strings::base64_encode($primes[1]->toBytes()),
            'Prime2' => Strings::base64_encode($primes[2]->toBytes()),
            'Exponent1' => Strings::base64_encode($exponents[1]->toBytes()),
            'Exponent2' => Strings::base64_encode($exponents[2]->toBytes()),
            'Coefficient' => Strings::base64_encode($coefficients[2]->toBytes())
        ]);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @param BigInteger $n
     * @param BigInteger $e
     * @param array $options optional
     * @return string
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = [])
    {
        if (!isset($options['hash'])) {
            throw new \InvalidArgumentException("DNSSEC keys require the options array have 'hash' as a key");
        }

        switch ($options['hash']) {
            case 'md5':
                $algo = 1;
                break;
            case 'sha1':
                $algo = 5;
                break;
            case 'sha256':
                $algo = 8;
                break;
            case 'sha512':
                $algo = 10;
                break;
            default:
                throw new UnsupportedAlgorithmException($options['hash'] . ' is not supported by this class');
        }

        $exponent = $e->toBytes();
        $exponentLength = strlen($exponent);
        $length = $exponentLength <= 255 ? chr($exponentLength) : pack('xn', $exponentLength);
        $key = $length . $exponent . $n->toBytes();
        return "$algo " . Strings::base64_encode($key);
    }
}