<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\DH;
use phpseclib\Crypt\DH\PublicKey;
use phpseclib\Crypt\DH\PrivateKey;
use phpseclib\Crypt\DH\Parameters;
use phpseclib\Crypt\EC;
use phpseclib\Math\BigInteger;

class Unit_Crypt_DHTest extends PhpseclibTestCase
{
    public function testParametersWithString()
    {
        $a = DH::createParameters('diffie-hellman-group1-sha1');
        $b = '-----BEGIN DH PARAMETERS-----
MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR
Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL
/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC
-----END DH PARAMETERS-----';
        $this->assertSame($b, $a);
    }

    public function testParametersWithInteger()
    {
        $a = DH::createParameters(512);
        $this->assertInternalType('string', $a);
    }

    public function testParametersWithBigIntegers()
    {
        $prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF';
        $prime = new BigInteger($prime, 16);
        $base = new BigInteger(2);
        $a = DH::createParameters($prime, $base);
        $b = '-----BEGIN DH PARAMETERS-----
MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR
Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL
/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC
-----END DH PARAMETERS-----';
        $this->assertSame($b, $a);
    }

    public function testCreateKey()
    {
        $param = DH::createParameters('diffie-hellman-group1-sha1');
        $key = DH::createKey($param);
        $this->assertInternalType('string', "$key");
        $this->assertInternalType('string', (string) $key->getPublicKey());
    }

    public function testLoadPrivate()
    {
        $a = DH::load('-----BEGIN PRIVATE KEY-----
MIIBIgIBADCBlQYJKoZIhvcNAQMBMIGHAoGBAP//////////yQ/aoiFowjTExmKL
gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt
bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR
7OZTgf//////////AgECBIGEAoGBALJhtp0aNlkpKTcY1qj519XB8CPc7aZii0xV
bbb/3R93sweVmk2PlkSqxc2kdcofhL8Ev0DJKxB40Ipdqja71VoBbDZ2nMzS0J6s
b6R8Z19Xazc0wq+p/wqalmnuCMBUBuuQ8aNNaW8FGwFwAI3I6CuQSsKObVDJO25m
eKDXQq5i
-----END PRIVATE KEY-----');
        $this->assertInstanceOf(PrivateKey::class, $a);
        $this->assertInstanceOf(PublicKey::class, $a->getPublicKey());
        $this->assertInstanceOf(Parameters::class, $a->getParameters());
    }

    public function testLoadPublic()
    {
        $a = DH::load('-----BEGIN PUBLIC KEY-----
MIIBHzCBlQYJKoZIhvcNAQMBMIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc
0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHC
ReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZT
gf//////////AgECA4GEAAKBgCsa1YmlaQIvbOuIi/6DKr7jsdMcv50u/Opemca5
i2REGZNPWmF3SRPrtq/4urrDRU0F2eQks7qnTkrauPK1/UvE1gwbqWrWgBko+6L+
Q3ADAIcv9LEmTBnSAOsCs1K9ExAmSv/T2/4+9dW28UYb+p/uV477d1wf+nCWS6VU
/gTm
-----END PUBLIC KEY-----');
        $this->assertInstanceOf(PublicKey::class, $a);
    }

    public function testLoadParameters()
    {
        $a = DH::load('-----BEGIN DH PARAMETERS-----
MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR
Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL
/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC
-----END DH PARAMETERS-----');
        $this->assertInstanceOf(Parameters::class, $a);
    }

    public function testComputeSecretWithPublicKey()
    {
        $ourPriv = DH::load('-----BEGIN PRIVATE KEY-----
MIIBIgIBADCBlQYJKoZIhvcNAQMBMIGHAoGBAP//////////yQ/aoiFowjTExmKL
gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt
bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR
7OZTgf//////////AgECBIGEAoGBALJhtp0aNlkpKTcY1qj519XB8CPc7aZii0xV
bbb/3R93sweVmk2PlkSqxc2kdcofhL8Ev0DJKxB40Ipdqja71VoBbDZ2nMzS0J6s
b6R8Z19Xazc0wq+p/wqalmnuCMBUBuuQ8aNNaW8FGwFwAI3I6CuQSsKObVDJO25m
eKDXQq5i
-----END PRIVATE KEY-----');
        $theirPub = DH::load('-----BEGIN PUBLIC KEY-----
MIIBHzCBlQYJKoZIhvcNAQMBMIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc
0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHC
ReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZT
gf//////////AgECA4GEAAKBgCsa1YmlaQIvbOuIi/6DKr7jsdMcv50u/Opemca5
i2REGZNPWmF3SRPrtq/4urrDRU0F2eQks7qnTkrauPK1/UvE1gwbqWrWgBko+6L+
Q3ADAIcv9LEmTBnSAOsCs1K9ExAmSv/T2/4+9dW28UYb+p/uV477d1wf+nCWS6VU
/gTm
-----END PUBLIC KEY-----');
        $this->assertInternalType('string', DH::computeSecret($ourPriv, $theirPub));
    }

    public function testComputeSecretWithP256PublicKey()
    {
        $ourPriv = EC::createKey('nistp256');
        $theirPub = EC::createKey('nistp256')->getPublicKey();
        $this->assertInternalType('string', DH::computeSecret($ourPriv, $theirPub));
    }

    public function testComputeSecretWithCurve25519PublicKey()
    {
        $ourPriv = EC::createKey('curve25519');
        $theirPub = EC::createKey('curve25519')->getPublicKey();
        $this->assertInternalType('string', DH::computeSecret($ourPriv, $theirPub));
    }
}
