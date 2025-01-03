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

namespace phpseclib3\Crypt\Common\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BigInteger;

/**
 * DNSSEC Formatted Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class DNSSEC
{
    /**
     * Return the algorithm name given the algorithm ID
     *
     * @param int $id
     * @return string
     */
    protected static function algorithmID2Name($id)
    {
        // see https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
        $algorithmMap = [
            1  => 'RSAMD5',
            2  => 'DH',
            3  => 'DSA',

            5  => 'RSASHA1',
            6  => 'DSA-NSEC3-SHA1',
            7  => 'RSASHA1-NSEC3-SHA1',
            8  => 'RSASHA256',

            10 => 'RSASHA512',

            12 => 'ECC-GOST', // GOST is a russian standard, see https://en.wikipedia.org/wiki/GOST_(block_cipher)
            13 => 'ECDSAP256SHA256',
            14 => 'ECDSAP384SHA384',
            15 => 'ED25519',
            16 => 'ED448',
            17 => 'SM2SM3', // SM2 / SM3 are chinese standards, see https://en.wikipedia.org/wiki/SM9_(cryptography_standard)

            23 => 'ECC-GOST12',
        ];
        if (!isset($algorithmMap[$id])) {
            throw new \RuntimeException("Algorithm $id does not correspond to a known algorithm");
        }
        return $algorithmMap[$id];
    }

    /**
     * Break a public or private key down into its constituent components
     *
     * @param string $key
     * @param string $password
     * @return array
     */
    public static function load($key, $password = '')
    {
        if (!Strings::is_stringable($key)) {
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        if (substr($key, 0, 19) == 'Private-key-format:') {
            $pieces = preg_split("#[\r\n]+#", trim($key));
            $new = [];
            foreach ($pieces as $piece) {
                list($key, $val) = explode(':', $piece);
                $new[$key] = trim($val);
            }
            $prettyName = substr($new['Algorithm'], strpos($new['Algorithm'], '(') + 1, -1);
            $new['Algorithm'] = (int) $new['Algorithm'];
            if (self::algorithmID2Name($new['Algorithm']) != $prettyName) {
                throw new \RuntimeException("Algorithm ID of $new[Algorithm] is $prettyName vs. " . self::algorithmID2Name($new['Algorithm']));
            }
            return $new;
        }
        if (!preg_match('# 3 \d+ #', $key)) {
            // "The Protocol Field MUST have value 3"
            //  -- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2
            throw new \RuntimeException('Unable to decode DNSSEC key');
        }
        $pos = strpos($key, ' 3 ');
        $key = substr($key, $pos + 3);
        $key = explode(' ', $key);
        $algorithm = array_shift($key);
        $key = trim(implode('', $key));
        if (!preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $key)) {
            throw new \RuntimeException('Key does not appear to be base64-encoded');
        }
        return [
            'Algorithm' => (int) $algorithm,
            'Key' => Strings::base64_decode($key)
        ];
    }

    /**
     * "Wrap" a public key appropriately
     *
     * @param string $key
     * @param string $type
     * @return string
     */
    protected static function wrapPrivateKey(array $arr)
    {
        $arr['Created'] = $arr['Publish'] = $arr['Activate'] = date('YmdHis');
        $output = "Private-key-format: v1.3\n";
        foreach ($arr as $key=>$val) {
            $output.= "$key: $val\n";
        }
        return rtrim($output);
    }
}
