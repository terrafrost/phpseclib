<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\File\ASN1;

class Unit_File_ASN1Test extends PhpseclibTestCase
{

    public function testIndefiniteLength()
    {
        $decoded = ASN1::decodeBER(file_get_contents(dirname(__FILE__) . '/ASN1/FE.pdf.p7m'));
        $this->assertCount(5, $decoded[0]['content'][1]['content'][0]['content']); // older versions would have returned 3
    }
}
