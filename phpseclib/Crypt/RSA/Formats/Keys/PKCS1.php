<?php

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN RSA PRIVATE KEY-----
 * -----BEGIN RSA PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\Exception\UnexpectedValueException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS1 extends Progenitor
{
    /**
     * Break a public or private key down into its constituent components
     */
    public static function load(string|array $key, #[SensitiveParameter] ?string $password = null): array
    {
        if (!is_string($key)) {
            throw new UnexpectedValueException('Key should be a string - not an array');
        }

        if (str_contains($key, 'PUBLIC')) {
            $components = ['isPublicKey' => true];
        } elseif (str_contains($key, 'PRIVATE')) {
            $components = ['isPublicKey' => false];
        } else {
            $components = [];
        }

        $key = parent::loadHelper($key, $password);

        try {
            $decoded = ASN1::decodeBER($key);
        } catch (\Exception $e) {
            throw new RuntimeException('Unable to decode BER', 0, $e);
        }

        try {
            $key = ASN1::map($decoded, Maps\RSAPrivateKey::MAP)->toArray();
        } catch (\Exception $e) {
            $key = false;
        }
        if (is_array($key)) {
            $components += [
                'modulus' => $key['modulus'],
                'publicExponent' => $key['publicExponent'],
                'privateExponent' => $key['privateExponent'],
                'primes' => [1 => $key['prime1'], $key['prime2']],
                'exponents' => [1 => $key['exponent1'], $key['exponent2']],
                'coefficients' => [2 => $key['coefficient']],
            ];
            if ($key['version'] == 'multi') {
                foreach ($key['otherPrimeInfos'] as $primeInfo) {
                    $components['primes'][] = $primeInfo['prime'];
                    $components['exponents'][] = $primeInfo['exponent'];
                    $components['coefficients'][] = $primeInfo['coefficient'];
                }
            }
            if (!isset($components['isPublicKey'])) {
                $components['isPublicKey'] = false;
            }
            return $components;
        }

        try {
            $key = ASN1::map($decoded, Maps\RSAPublicKey::MAP)->toArray();
        } catch (\Exception $e) {
            throw new RuntimeException('Unable to perform ASN1 mapping');
        }

        if (!isset($components['isPublicKey'])) {
            $components['isPublicKey'] = true;
        }

        $components = $components + $key;
        foreach ($components as &$val) {
            if ($val instanceof BigInteger) {
                $val = self::makePositive($val);
            }
            if (is_array($val)) {
                foreach ($val as &$subval) {
                    if ($subval instanceof BigInteger) {
                        $subval = self::makePositive($subval);
                    }
                }
            }
        }

        return $components + $key;
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, #[SensitiveParameter] ?string $password = null, array $options = []): string
    {
        $num_primes = count($primes);
        $key = [
            'version' => $num_primes == 2 ? 'two-prime' : 'multi',
            'modulus' => $n,
            'publicExponent' => $e,
            'privateExponent' => $d,
            'prime1' => $primes[1],
            'prime2' => $primes[2],
            'exponent1' => $exponents[1],
            'exponent2' => $exponents[2],
            'coefficient' => $coefficients[2],
        ];
        for ($i = 3; $i <= $num_primes; $i++) {
            $key['otherPrimeInfos'][] = [
                'prime' => $primes[$i],
                'exponent' => $exponents[$i],
                'coefficient' => $coefficients[$i],
            ];
        }

        $key = ASN1::encodeDER($key, Maps\RSAPrivateKey::MAP);

        return self::wrapPrivateKey($key, 'RSA', $password, $options);
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e): string
    {
        $key = [
            'modulus' => $n,
            'publicExponent' => $e,
        ];

        $key = ASN1::encodeDER($key, Maps\RSAPublicKey::MAP);

        return self::wrapPublicKey($key, 'RSA');
    }

    /**
     * Negative numbers make no sense in RSA so convert them to positiveAdd commentMore actions
     *
     * @param BigInteger $x
     * @return string
     */
    private static function makePositive(BigInteger $x): BigInteger
    {
        return $x->isNegative() ?
            new BigInteger($x->toBytes(true), 256) :
            $x;
    }
}
