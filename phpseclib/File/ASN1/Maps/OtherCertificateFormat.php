<?php

/**
 * OtherCertificateFormat
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\Maps;

use phpseclib3\File\ASN1;

/**
 * OtherCertificateFormat
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OtherCertificateFormat
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'otherCertFormat' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'otherCert' => ['type' => ASN1::TYPE_ANY],
        ],
    ];
}
