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

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\DNSSEC as Progenitor;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Curves\Ed448;
use phpseclib3\Crypt\EC\Curves\secp256r1;
use phpseclib3\Crypt\EC\Curves\secp384r1;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\Math\BigInteger;

/**
 * DNSSEC (RFC4034) Formatted EC Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class DNSSEC extends Progenitor
{
    use Common;

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
            case 13:
                $curveName = 'nistp256';
                break;
            case 14:
                $curveName = 'nistp384';
                break;
            case 15:
                $curveName = 'Ed25519';
                break;
            case 16:
                $curveName = 'Ed448';
                break;
            default:
                throw new UnsupportedAlgorithmException(self::algorithmID2Name($key['Algorithm']) . ' is not supported by this class');
        }

        $curve = self::loadCurveByParam(['namedCurve' => $curveName]);
        $components = ['curve' => $curve];

        if (isset($key['Private-key-format'])) {
            $privateKey = Strings::base64_decode($key['PrivateKey']);
            if ($key['Algorithm'] >= 15) { // Ed25519 + Ed448
                $arr = $curve->extractSecret($privateKey);
                $components['dA'] = $arr['dA'];
                $components['secret'] = $arr['secret'];
            } else {
                $dA = new BigInteger($privateKey, 256);
                $curve->rangeCheck($dA);
                $components['dA'] = $dA;
            }
            $components['QA'] = $curve->multiplyPoint($curve->getBasePoint(), $components['dA']);
            return $components;
        }
        if ($key['Algorithm'] < 15) { // nistp256 + nistp384
            $key['Key'] = "\0\4$key[Key]";
        }
        $components['QA'] = self::extractPoint($key['Key'], $curve);

        return $components;
    }

    /**
     * Convert an EC public key to the appropriate format
     *
     * Public keys produced by this method can't be read by ::load() because ::load()
     * is validating additional optional parameters that this doesn't (currently) set
     *
     * @param BaseCurve $curve
     * @param \phpseclib3\Math\Common\FiniteField\Integer[] $publicKey
     * @param array $options optional
     * @return string
     */
    public static function savePublicKey(BaseCurve $curve, array $publicKey, array $options = [])
    {
        switch (true) {
            case $curve instanceof secp256r1:
                $algo = 13;
            case $curve instanceof secp384r1:
                $algo = isset($algo) ? $algo : 14;
                return "$algo " . Strings::base64_encode($publicKey[0]->toBytes() . $publicKey[1]->toBytes());//Strings::base64_encode(substr($curve->encodePoint($publicKey), 2));
            case $curve instanceof Ed25519:
                $algo = 15;
            case $curve instanceof Ed448:
                $algo = isset($algo) ? $algo : 15;
                return "$algo " . Strings::base64_encode($curve->encodePoint($publicKey));
        }

        $reflect = new \ReflectionClass($curve);
        $curveName = $reflect->isFinal() ?
            $reflect->getParentClass()->getShortName() :
            $reflect->getShortName();
        throw new UnsupportedCurveException("$curveName is not a supported curve");
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @param BigInteger $privateKey
     * @param Ed25519 $curve
     * @param \phpseclib3\Math\Common\FiniteField\Integer[] $publicKey
     * @param string $secret optional
     * @param string $password optional
     * @param array $options optional
     * @return string
     */
    public static function savePrivateKey(BigInteger $privateKey, BaseCurve $curve, array $publicKey, $secret = null, $password = '', array $options = [])
    {
        switch (true) {
            case $curve instanceof secp256r1:
                $algo = '13 (ECDSAP256SHA256)';
            case $curve instanceof secp384r1:
                $algo = isset($algo) ? $algo : '14 (ECDSAP384SHA384)';
                $private = $privateKey->toBytes();
                break;
            case $curve instanceof Ed25519:
                $algo = '15 (ED25519)';
            case $curve instanceof Ed448:
                $algo = '16 (ED448)';
                $private = $secret;
                break;
            default:
                $reflect = new \ReflectionClass($curve);
                $curveName = $reflect->isFinal() ?
                    $reflect->getParentClass()->getShortName() :
                    $reflect->getShortName();
                throw new UnsupportedCurveException("$curveName is not a supported curve");
        }
        return self::wrapPrivateKey([
            'Algorithm' => $algo,
            'PrivateKey' => Strings::base64_encode($private)
        ]);
    }
}