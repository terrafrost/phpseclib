<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\File\ASN1;
use phpseclib4\File\CMS;
use phpseclib4\File\CMS\SignedData;
use phpseclib4\File\X509;
use phpseclib4\Tests\PhpseclibTestCase;

class SignedDataTest extends PhpseclibTestCase
{
    public function testSMIMECapabilities(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIFmAYJKoZIhvcNAQcCoIIFiTCCBYUCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBoIIDIjCCAx4wggHRoAMCAQICFEqEwHgUhgvn+HxPMOmo094oXmy2MEIG
CSqGSIb3DQEBCjA1oA0wCwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCG
SAFlAwQCAaIDAgEgowMCAQEwFDESMBAGA1UECgwJcGhwc2VjbGliMB4XDTI1MTIy
NDIxMDYxNloXDTI2MTIyNDIxMDYxNlowFDESMBAGA1UECgwJcGhwc2VjbGliMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlGi2OtxhNCyzGZcjUuydfjsy
d+T9wQBlLQsEf0rHrKIqFZvZAgGAqyY12qCR9pg28nuRYtlnQ+2haMDZDcCBHTRg
RFy0c/AhyUDLAz6a++tKJ3bVmUWQGfoIp0/hxu2EqRA+GWBCoN7d8+arH/3Spfg8
I9ImmftqElMAF6Tj2h4bGFTM04zKncK9KzTI79t/H/6NEZZGaAaCNZc1y5Tmb+j3
zuqnbtGTSR654u2m2kTMOnZrPKO/SiqcMgxDkxlom77OG83J3NvZiWnEyQ3w8P4A
M/UhZizkNpxryckf99ddO7K7bdJKWBXfzX3RTr7rabDkAxqoefEh/sDgp2PCnQID
AQABMEIGCSqGSIb3DQEBCjA1oA0wCwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEI
MAsGCWCGSAFlAwQCAaIDAgEgowMCAQEDggEBAANwXpYkoyCWY9r2zVukItxE90J1
JE5Xo4aGevttEKSpUa3HDM3TKMfsLozk1PZbnEAeB4OcROYXuwL3AcqO4BDCLhBE
mSOSao19n6f1zpocKj4gz3yB5NoJrLA1aigZn4xwcu8MrC0l4lCnRZ2p/Ada5cTL
X+FCSiGUYZ/YiyKol9pcmou24C3Ven8VBbGoqWjQkNDEkKXhvwf+xvgdRFlVIVeg
jQDBR+/kHUugxDHNy6+ohX+3qpzRu5PZ6rZrINjVdNOuGkQwOSQ2dkUY3Hoom96o
0Finww4o81WN2eWmKGHk+K3cUlIl49WWIU2sYfO4WUiV6JCXVHP84q5PI1gxggI8
MIICOAIBATAsMBQxEjAQBgNVBAoMCXBocHNlY2xpYgIUSoTAeBSGC+f4fE8w6ajT
3ihebLYwCwYJYIZIAWUDBAIBoIHkMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
HAYJKoZIhvcNAQkFMQ8XDTI1MTIyNDIxMDc0OFowLwYJKoZIhvcNAQkEMSIEILpv
HE/4wsEEplUEfTyrPUDWl4FW9MOJQslIs9k7o2cuMHkGCSqGSIb3DQEJDzFsMGow
CwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcN
AwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0GCCqG
SIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAJK+lppTBje8/2Nr7LZoSXrcXhfO
1hQomL08Bp3m6miHoRmwuwWSZsOGOYBmAHzKnaLLvnIMAKfOi6Gv+4LRna3Zyynd
9wxNEXnx8vQf8Wyj7TBziEHXT78xDPckAdAr6DEIRqw6RrMYaMUeKGJde2DAzp6z
JD3rCxBtB8YZeQ9jKdbNh0PLfHUnrQkv+OOJM04HI4qRepTOAGrBlbCSnQdSheqI
M0OBYZe9ntgapIKsumKkfhOzo65F41fsyi2n6U8gLE0m6QYy+bMI0ElWXfjDA5eT
2kPMf5mvGDoVHc4xL+HZrNfFCPxneRBsB6fhZHfhKBp5E3yhDKStGe2O1Vs=
-----END CMS-----');
        $result = $cms->toArray();
        $this->assertIsArray($result);
        $cms = SignedData::load($result);
        $this->assertCount(8, $cms->getSigners()[0]->getSignedAttr('pkcs-9-at-smimeCapabilities')[0]);
    }

    public function testAlgorithmChange(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIFmAYJKoZIhvcNAQcCoIIFiTCCBYUCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBoIIDIjCCAx4wggHRoAMCAQICFEqEwHgUhgvn+HxPMOmo094oXmy2MEIG
CSqGSIb3DQEBCjA1oA0wCwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCG
SAFlAwQCAaIDAgEgowMCAQEwFDESMBAGA1UECgwJcGhwc2VjbGliMB4XDTI1MTIy
NDIxMDYxNloXDTI2MTIyNDIxMDYxNlowFDESMBAGA1UECgwJcGhwc2VjbGliMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlGi2OtxhNCyzGZcjUuydfjsy
d+T9wQBlLQsEf0rHrKIqFZvZAgGAqyY12qCR9pg28nuRYtlnQ+2haMDZDcCBHTRg
RFy0c/AhyUDLAz6a++tKJ3bVmUWQGfoIp0/hxu2EqRA+GWBCoN7d8+arH/3Spfg8
I9ImmftqElMAF6Tj2h4bGFTM04zKncK9KzTI79t/H/6NEZZGaAaCNZc1y5Tmb+j3
zuqnbtGTSR654u2m2kTMOnZrPKO/SiqcMgxDkxlom77OG83J3NvZiWnEyQ3w8P4A
M/UhZizkNpxryckf99ddO7K7bdJKWBXfzX3RTr7rabDkAxqoefEh/sDgp2PCnQID
AQABMEIGCSqGSIb3DQEBCjA1oA0wCwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEI
MAsGCWCGSAFlAwQCAaIDAgEgowMCAQEDggEBAANwXpYkoyCWY9r2zVukItxE90J1
JE5Xo4aGevttEKSpUa3HDM3TKMfsLozk1PZbnEAeB4OcROYXuwL3AcqO4BDCLhBE
mSOSao19n6f1zpocKj4gz3yB5NoJrLA1aigZn4xwcu8MrC0l4lCnRZ2p/Ada5cTL
X+FCSiGUYZ/YiyKol9pcmou24C3Ven8VBbGoqWjQkNDEkKXhvwf+xvgdRFlVIVeg
jQDBR+/kHUugxDHNy6+ohX+3qpzRu5PZ6rZrINjVdNOuGkQwOSQ2dkUY3Hoom96o
0Finww4o81WN2eWmKGHk+K3cUlIl49WWIU2sYfO4WUiV6JCXVHP84q5PI1gxggI8
MIICOAIBATAsMBQxEjAQBgNVBAoMCXBocHNlY2xpYgIUSoTAeBSGC+f4fE8w6ajT
3ihebLYwCwYJYIZIAWUDBAIBoIHkMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
HAYJKoZIhvcNAQkFMQ8XDTI1MTIyNDIxMDc0OFowLwYJKoZIhvcNAQkEMSIEILpv
HE/4wsEEplUEfTyrPUDWl4FW9MOJQslIs9k7o2cuMHkGCSqGSIb3DQEJDzFsMGow
CwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcN
AwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0GCCqG
SIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAJK+lppTBje8/2Nr7LZoSXrcXhfO
1hQomL08Bp3m6miHoRmwuwWSZsOGOYBmAHzKnaLLvnIMAKfOi6Gv+4LRna3Zyynd
9wxNEXnx8vQf8Wyj7TBziEHXT78xDPckAdAr6DEIRqw6RrMYaMUeKGJde2DAzp6z
JD3rCxBtB8YZeQ9jKdbNh0PLfHUnrQkv+OOJM04HI4qRepTOAGrBlbCSnQdSheqI
M0OBYZe9ntgapIKsumKkfhOzo65F41fsyi2n6U8gLE0m6QYy+bMI0ElWXfjDA5eT
2kPMf5mvGDoVHc4xL+HZrNfFCPxneRBsB6fhZHfhKBp5E3yhDKStGe2O1Vs=
-----END CMS-----');
        $ref = &$cms['content']['signerInfos'][0]['signedAttrs'][3]['value'][0];
        for ($i = 0; $i < count($ref); $i++) {
            $ref[$i]['algorithm'] = new ASN1\Types\OID('aes192-CBC-PAD');
            unset($ref[$i]['parameters']);
        }
        $new = CMS::load("$cms");
        $attr = $new->getSigners()[0]->getSignedAttr('pkcs-9-at-smimeCapabilities')[0];
        foreach ($attr as $algo) {
            $this->assertEquals('aes192-CBC-PAD', (string) $algo['algorithm']);
        }
    }

    public function testValidateSignature(): void
    {
        $cms = CMS::load(file_get_contents(__DIR__ . '/FE.pdf.p7m'));
        // if we didn't pass false to validateSignature() it'd test to see if the cert it found was signed
        // by a CA cert (or that it *was* a CA cert)
        $this->assertTrue($cms->validateSignature(false));
    }

    public function testDetachedSigWithTwoDetachedCerts(): void
    {
        // openssl cms -sign -in test.txt -out cms-signed.pem -outform PEM -signer small.pub -inkey small.priv -md sha1 -signer small2.pub -inkey small2.priv -md sha1 -nocerts -nosmimecap
        $cms = CMS::load('-----BEGIN CMS-----
MIIB+AYJKoZIhvcNAQcCoIIB6TCCAeUCAQExCTAHBgUrDgMCGjALBgkqhkiG9w0B
BwExggHGMIHgAgEBMC4wFjEUMBIGA1UECgwLcGhwc2VjbGliIEECFGxZKrSPvkiI
Lahro1u4RUUwOdgxMAcGBSsOAwIaoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
ATAcBgkqhkiG9w0BCQUxDxcNMjUxMjMxMDIxMzQ1WjAjBgkqhkiG9w0BCQQxFgQU
0hYWktbKp2OWDBMRzMfrQ0gwHv4wCQYHKoZIzj0EAQQ4MDYCGQCGTfe/yNU8/gYz
G8lYgecLV1tQWa3IISECGQD0qfIIKVqlnR0/hdxuv2mSjO9gAz0YjykwgeACAQEw
LjAWMRQwEgYDVQQKDAtwaHBzZWNsaWIgQgIUW9t6BBtN4h8QFmRBnufZyOMW5Yow
BwYFKw4DAhqgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
BTEPFw0yNTEyMzEwMjEzNDVaMCMGCSqGSIb3DQEJBDEWBBTSFhaS1sqnY5YMExHM
x+tDSDAe/jAJBgcqhkjOPQQBBDgwNgIZAPfgyQHK5WcUjhJmNQIe/nIonN5gtg2C
YwIZAI+8GOohj7FHDMbR3M537Mlen8hFP9LwfQ==
-----END CMS-----');
        $cms->addCertificate(X509::load('-----BEGIN CERTIFICATE-----
MIIBLDCCASCgAwIBAgIUbFkqtI++SIgtqGujW7hFRTA52DEwAwYBADAWMRQwEgYD
VQQKDAtwaHBzZWNsaWIgQTAeFw0yNTEyMzEwMjAxMTRaFw0yNjEyMzEwMjAxMTRa
MBYxFDASBgNVBAoMC3BocHNlY2xpYiBBMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQED
MgAEyR5pmecqhmsF2kTe9YfHUO0ahwP4qa24b61pZTwMtcnm/Znb92PinY7lHhLZ
kMqIo2MwYTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUWlpOWvb/vvPuZRS8dUa/hTmmdiwwHwYDVR0jBBgwFoAUWlpOWvb/vvPuZRS8
dUa/hTmmdiwwAwYBAAMBAA==
-----END CERTIFICATE-----'));
        $cms->addCertificate(X509::load('-----BEGIN CERTIFICATE-----
MIIBLDCCASCgAwIBAgIUW9t6BBtN4h8QFmRBnufZyOMW5YowAwYBADAWMRQwEgYD
VQQKDAtwaHBzZWNsaWIgQjAeFw0yNTEyMzEwMjEyNDdaFw0yNjEyMzEwMjEyNDda
MBYxFDASBgNVBAoMC3BocHNlY2xpYiBCMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQED
MgAEzlqE9I12rZWDf0xAhvqsrU8YmAExbdGjM6HB3yrcKsiAXwAYUeYe6g9gzBRn
39Mto2MwYTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUtCvFSvWQQvGqBHJUybcPA9iklr0wHwYDVR0jBBgwFoAUtCvFSvWQQvGqBHJU
ybcPA9iklr0wAwYBAAMBAA==
-----END CERTIFICATE-----'));
        $cms->attach("hello, world!\r\n");
        $this->assertTrue($cms->validateSignature(false));
    }

    public function testX509Match(): void
    {
        $cms = CMS::load(file_get_contents(__DIR__ . '/FE.pdf.p7m'));
        $temp = new X509();
        $cms['content']['certificates'][0]['certificate'] = $temp;
        $cms = (string) $cms;
        $cms = CMS::load($cms);
        $this->assertSame((string) $cms['content']['certificates'][0]['certificate'], "$temp");
    }

    public function testPostalAddress(): void
    {
        $cms = new SignedData('hello, world!');
        $x509 = new X509();
        $x509->addDNProp('id-at-postalAddress', [
            'John Doe',
            '111 Anywhere St',
            'Anytown, TX, USA',
        ]);
        $signer = $cms->addSigner($x509);
        $cms = CMS::load("$cms");
        $this->assertIsArray($cms->toArray());
    }
}
