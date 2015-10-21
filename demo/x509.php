<?php
include('File/X509.php');
include('Crypt/RSA.php');

// create private key / x.509 cert for stunnel / website
$privKey = new Crypt_RSA();
extract($privKey->createKey());
$privKey->loadKey($privatekey);

$pubKey = new Crypt_RSA();
$pubKey->loadKey($publickey);
$pubKey->setPublicKey();

$subject = new File_X509();
$subject->setDNProp('id-at-organizationName', 'phpseclib demo cert');
$subject->setPublicKey($pubKey);

$issuer = new File_X509();
$issuer->setPrivateKey($privKey);
$issuer->setDN($subject->getDN());

$x509 = new File_X509();

$x509->loadX509($x509->saveX509($x509->sign($issuer, $subject)));

$ext = array(
    array('statementId' => 'id-etsi-qcs-QcCompliance'),
    array('statementId' => 'id-etsi-qcs-QcSSCD'),
    array(
        'statementId' => 'id-etsi-qcs-QcRetentionPeriod',
        'statementInfo' => new Math_BigInteger(20)
    ),
    array(
        'statementId' => 'id-etsi-qcs-QcLimitValue',
        'statementInfo' => array(
            'currency' => array('alphabetic' => 'USD'),
            'amount' => 2000,
            'exponent' => 0
        )
    )
);
$x509->setExtension('id-pe-qcStatements', $ext);

$ext = array(array(
    'type' => 'id-pda-dateOfBirth',
    'value' => array(array(
        'generalTime' => 'September 11, 2001 8:46am'
    ))
));
$x509->setExtension('id-ce-subjectDirectoryAttributes', $ext);

$keyIdentifier = 'zzz';

$ext = array(
    'keyIdentifier' => $keyIdentifier,
    'authorityCertIssuer' => array(array('directoryName' => $x509->currentCert['tbsCertificate']['issuer'])),
    'authorityCertSerialNumber' => $x509->currentCert['tbsCertificate']['serialNumber']
);
$x509->setExtension('id-ce-authorityKeyIdentifier', $ext);

$ext = $keyIdentifier; // the same as the above since this is a self-signed cert
$x509->setExtension('id-ce-subjectKeyIdentifier', $ext);

$ext = array(array(
    'accessMethod' => 'id-ad-ocsp',
    'accessLocation' => array('uniformResourceIdentifier' => 'http://ocsp.sc.infocert.it/')
));
$x509->setExtension('id-pe-authorityInfoAccess', $ext);

$result = $x509->sign($issuer, $x509);

echo "the stunnel.pem contents are as follows:\r\n\r\n";
echo $privKey->getPrivateKey();
echo "\r\n";
echo $x509->saveX509($result);
echo "\r\n";