<?php
/**
 * PKCS1\Version
 *
 * PHP version 5
 *
 * @category  File
 * @package   ASN1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\File\ASN1\PKCS1;

use phpseclib\File\ASN1;

/**
 * PKCS1\Version
 *
 * @package ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Version
{
    // version must be multi if otherPrimeInfos present
    const MAP = [
        'type'    => ASN1::TYPE_INTEGER,
        'mapping' => ['two-prime', 'multi']
    ];
}