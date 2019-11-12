<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\File\ASN1;

class Unit_File_ASN1Test extends PhpseclibTestCase
{
    /**
     * older versions of ASN1 didn't handle indefinite length tags very well
     */
    public function testIndefiniteLength()
    {
$a = pack('H*', '206469206365727469666963617a696f6e65313c303a06035504031333526567696f6e65204c6f6d6261726469612043657274696669636174696f6e20417574686f7269747920436974746164696e69301e170d3038313031383030303030305a170d313431');


//$asn1 = new ASN1();
$r = ASN1::decodeBER($a);
print_r($r);
exit;

        $decoded = ASN1::decodeBER(file_get_contents(dirname(__FILE__) . '/ASN1/FE.pdf.p7m'));
        $this->assertCount(5, $decoded[0]['content'][1]['content'][0]['content']); // older versions would have returned 3
    }
}
