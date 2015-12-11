<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'File/X509.php';

class Unit_File_X509_X509Test extends PhpseclibTestCase
{
    private function _encodeOID($oid)
    {
        if ($oid === false) {
            user_error('Invalid OID');
            return false;
        }
        $value = '';
        $parts = explode('.', $oid);
        $value = chr(40 * $parts[0] + $parts[1]);
        for ($i = 2; $i < count($parts); $i++) {
            $temp = '';
            if (!$parts[$i]) {
                $temp = "\0";
            } else {
                while ($parts[$i]) {
                    $temp = chr(0x80 | ($parts[$i] & 0x7F)) . $temp;
                    $parts[$i] >>= 7;
                }
                $temp[strlen($temp) - 1] = $temp[strlen($temp) - 1] & chr(0x7F);
            }
            $value.= $temp;
        }
        return $value;
    }

    public function testGetOID()
    {
        $x509 = new File_X509();
        $this->assertEquals($x509->getOID('2.16.840.1.101.3.4.2.1'), '2.16.840.1.101.3.4.2.1');
        $this->assertEquals($x509->getOID('id-sha256'), '2.16.840.1.101.3.4.2.1');
        $this->assertEquals($x509->getOID('zzz'), 'zzz');
    }
}
