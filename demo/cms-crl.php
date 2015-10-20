<?php
include('File/CMS.php');

$cms = new File_CMS();
$r = $cms->load(file_get_contents('revocato.p7m'));

$certs = $cms->getSigningCerts();
foreach ($certs as $cert) {
	$x509 = new File_X509();
	$x509->loadX509($cert);
	if ($addresses = $x509->getExtension('id-ce-cRLDistributionPoints')) {
		foreach ($addresses as $address) {
			if (parse_url($address['distributionPoint']['fullName'][0]['uniformResourceIdentifier'], PHP_URL_SCHEME) != 'http') {
				continue;
			}
			if ($data = file_get_contents($address['distributionPoint']['fullName'][0]['uniformResourceIdentifier'])) {
				$crl = new File_X509();
				$crl->loadCRL($data);
				echo $crl->getRevoked($x509->currentCert['tbsCertificate']['serialNumber']) ? 'bad cert' : 'good cert';
			}
		}
	}
}