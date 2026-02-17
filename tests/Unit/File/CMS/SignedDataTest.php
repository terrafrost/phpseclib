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

    public testValidateSignature(): void
    {
        $cms = CMS::load(file_get_contents(__DIR__ . '/FE.pdf.p7m'));
        // if we didn't pass false to validateSignature() it'd test to see if the cert it found was signed
        // by a CA cert (or that it *was* a CA cert)
        $this->assertTrue($cms->validateSignature(false));
    }
}
