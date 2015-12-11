<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'File/X509.php';

class Unit_File_X509_X509Test extends PhpseclibTestCase
{
    /**
     * @group github705
     */
    public function testSaveNullRSAParam()
    {
        $privKey = new Crypt_RSA();
        $privKey->loadKey('-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDMswfEpAgnUDWA74zZw5XcPsWh1ly1Vk99tsqwoFDkLF7jvXy1
dDLHYfuquvfxCgcp8k/4fQhx4ubR8bbGgEq9B05YRnViK0R0iBB5Ui4IaxWYYhKE
8xqAEH2fL+/7nsqqNFKkEN9KeFwc7WbMY49U2adlMrpBdRjk1DqIEW3QTwIDAQAB
AoGBAJ+83cT/1DUJjJcPWLTeweVbPtJp+3Ku5d1OdaGbmURVs764scbP5Ihe2AuF
V9LLZoe/RdS9jYeB72nJ3D3PA4JVYYgqMOnJ8nlUMNQ+p0yGl5TqQk6EKLI8MbX5
kQEazNqFXsiWVQXubAd5wjtb6g0n0KD3zoT/pWLES7dtUFexAkEA89h5+vbIIl2P
H/NnkPie2NWYDZ1YiMGHFYxPDwsd9KCZMSbrLwAhPg9bPgqIeVNfpwxrzeksS6D9
P98tJt335QJBANbnCe+LhDSrkpHMy9aOG2IdbLGG63MSRUCPz8v2gKPq3kYXDxq6
Y1iqF8N5g0k5iirHD2qlWV5Q+nuGvFTafCMCQQC1wQiC0IkyXEw/Q31RqI82Dlcs
5rhEDwQyQof3LZEhcsdcxKaOPOmKSYX4A3/f9w4YBIEiVQfoQ1Ig1qfgDZklAkAT
TQDJcOBY0qgBTEFqbazr7PScJR/0X8m0eLYS/XqkPi3kYaHLpr3RcsVbmwg9hVtx
aBtsWpliLSex/HHhtRW9AkBGcq67zKmEpJ9kXcYLEjJii3flFS+Ct/rNm+Hhm1l7
4vca9v/F2hGVJuHIMJ8mguwYlNYzh2NqoIDJTtgOkBmt
-----END RSA PRIVATE KEY-----');

        $pubKey = new Crypt_RSA();
        $pubKey->loadKey($privKey->getPublicKey());
        $pubKey->setPublicKey();

        $subject = new File_X509();
        $subject->setDNProp('id-at-organizationName', 'phpseclib demo cert');
        $subject->setPublicKey($pubKey);

        $issuer = new File_X509();
        $issuer->setPrivateKey($privKey);
        $issuer->setDN($subject->getDN());

        $x509 = new File_X509();

        $result = $x509->sign($issuer, $subject);
        $cert = $x509->saveX509($result);
        $cert = $x509->loadX509($cert);

        $this->assertArrayHasKey('parameters', $cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']);
        $this->assertArrayHasKey('parameters', $cert['signatureAlgorithm']);
        $this->assertArrayHasKey('parameters', $cert['tbsCertificate']['signature']);
    }

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
