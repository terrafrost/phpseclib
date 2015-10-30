<?php

include_once('File/ASN1.php');
include_once('File/X509.php');
include_once('Crypt/RSA.php');

class File_CMS extends File_X509 // File_CMS_SignedData
{
    var $currentCMS;
    var $oids;

    var $ContentInfo;
    var $SignedData;

    var $SigningCertificate;
    var $SigningCertificateV2;

    var $signatureSubjects;
    var $certs;

    var $baseSignedData;
    var $baseSignedInfo;
    var $hash = 'sha256';
    var $keys;

    var $signingCerts;
    var $essSigningCerts;

    function File_CMS()
    {
        parent::File_X509();

        $ContentType = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $this->ContentInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'contentType' => $ContentType,
                'content' => array(
                    'type' => FILE_ASN1_TYPE_ANY,
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true
                )
            )
        );

        $CMSVersion = array(
            'type'    => FILE_ASN1_TYPE_INTEGER,
            'mapping' => array('v0', 'v1', 'v2', 'v4', 'v5')
        );

        $AlgorithmIdentifier = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'algorithm'  => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                'parameters' => array(
                                    'type'     => FILE_ASN1_TYPE_ANY,
                                    'optional' => true
                                )
            )
        );


        $DigestAlgorithmIdentifier = $AlgorithmIdentifier;

        $DigestAlgorithmIdentifiers = array(
            'type' => FILE_ASN1_TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $DigestAlgorithmIdentifier
        );

        $EncapsulatedContentInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'eContentType' => $ContentType,
                'eContent' => array(
                                  'type' => FILE_ASN1_TYPE_OCTET_STRING,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true
                              )
            )
        );

        $CertificateSerialNumber = array('type' => FILE_ASN1_TYPE_INTEGER);

        $AttCertValidityPeriod = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'notBeforeTime' => array('type' => FILE_ASN1_TYPE_GENERALIZED_TIME),
                'notAfterTime' => array('type' => FILE_ASN1_TYPE_GENERALIZED_TIME)
            )
        );

        $UniqueIdentifier = array('type' => FILE_ASN1_TYPE_BIT_STRING);

        $AttributeType = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $Attribute = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'type' => $AttributeType,
                'value'=> array(
                              'type'     => FILE_ASN1_TYPE_SET,
                              'min'      => 1,
                              'max'      => -1,
                              'children' => $this->AttributeValue
                          )
            )
        );

        $Attributes = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $AnotherName = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'type-id' => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                 'value'   => array(
                                  'type' => FILE_ASN1_TYPE_ANY,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true
                              )
            )
        );

        $ExtensionAttribute = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'extension-attribute-type'  => array(
                                                    'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                                    'constant' => 0,
                                                    'optional' => true,
                                                    'implicit' => true
                                                ),
                 'extension-attribute-value' => array(
                                                    'type' => FILE_ASN1_TYPE_ANY,
                                                    'constant' => 1,
                                                    'optional' => true,
                                                    'explicit' => true
                                                )
            )
        );

        $ExtensionAttributes = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => 256, // ub-extension-attributes
            'children' => $ExtensionAttribute
        );

        $BuiltInDomainDefinedAttribute = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'type'  => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING),
                 'value' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $BuiltInDomainDefinedAttributes = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-domain-defined-attributes
            'children' => $BuiltInDomainDefinedAttribute
        );

        $OrganizationalUnitNames = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-organizational-units
            'children' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
        );

        $PersonalName = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'children' => array(
                'surname'              => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 0,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'given-name'           => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 1,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'initials'             => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 2,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'generation-qualifier' => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 3,
                                           'optional' => true,
                                           'implicit' => true
                                         )
            )
        );

        $NumericUserIdentifier = array('type' => FILE_ASN1_TYPE_NUMERIC_STRING);

        $OrganizationName = array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING);

        $PrivateDomainName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'numeric'   => array('type' => FILE_ASN1_TYPE_NUMERIC_STRING),
                'printable' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $TerminalIdentifier = array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING);

        $NetworkAddress = array('type' => FILE_ASN1_TYPE_NUMERIC_STRING);

        $AdministrationDomainName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            // if class isn't present it's assumed to be FILE_ASN1_CLASS_UNIVERSAL or
            // (if constant is present) FILE_ASN1_CLASS_CONTEXT_SPECIFIC
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 2,
            'children' => array(
                'numeric'   => array('type' => FILE_ASN1_TYPE_NUMERIC_STRING),
                'printable' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $CountryName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            // if class isn't present it's assumed to be FILE_ASN1_CLASS_UNIVERSAL or
            // (if constant is present) FILE_ASN1_CLASS_CONTEXT_SPECIFIC
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 1,
            'children' => array(
                'x121-dcc-code'        => array('type' => FILE_ASN1_TYPE_NUMERIC_STRING),
                'iso-3166-alpha2-code' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $BuiltInStandardAttributes =  array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'country-name'               => array('optional' => true) + $CountryName,
                'administration-domain-name' => array('optional' => true) + $AdministrationDomainName,
                'network-address'            => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NetworkAddress,
                'terminal-identifier'        => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $TerminalIdentifier,
                'private-domain-name'        => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $PrivateDomainName,
                'organization-name'          => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationName,
                'numeric-user-identifier'    => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NumericUserIdentifier,
                'personal-name'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $PersonalName,
                'organizational-unit-names'  => array(
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationalUnitNames
            )
        );

        $ORAddress = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'built-in-standard-attributes'       => $BuiltInStandardAttributes,
                 'built-in-domain-defined-attributes' => array('optional' => true) + $BuiltInDomainDefinedAttributes,
                 'extension-attributes'               => array('optional' => true) + $ExtensionAttributes
            )
        );

        $EDIPartyName = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'nameAssigner' => array(
                                    'constant' => 0,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString,
                 // partyName is technically required but File_ASN1 doesn't currently support non-optional constants and
                 // setting it to optional gets the job done in any event.
                 'partyName'    => array(
                                    'constant' => 1,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString
            )
        );

        $GeneralName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'otherName'                 => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $AnotherName,
                'rfc822Name'                => array(
                                                 'type' => FILE_ASN1_TYPE_IA5_STRING,
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'dNSName'                   => array(
                                                 'type' => FILE_ASN1_TYPE_IA5_STRING,
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'x400Address'               => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $ORAddress,
                'directoryName'             => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $this->Name,
                'ediPartyName'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $EDIPartyName,
                'uniformResourceIdentifier' => array(
                                                 'type' => FILE_ASN1_TYPE_IA5_STRING,
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'iPAddress'                 => array(
                                                 'type' => FILE_ASN1_TYPE_OCTET_STRING,
                                                 'constant' => 7,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'registeredID'              => array(
                                                 'type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER,
                                                 'constant' => 8,
                                                 'optional' => true,
                                                 'implicit' => true
                                               )
            )
        );

        $GeneralNames = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $GeneralName
        );

        $IssuerSerial = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'issuer' => $GeneralNames,
                'serialNumber' => $CertificateSerialNumber
            )
        );

        $ExtendedCertificateInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version' => array('type' => FILE_ASN1_TYPE_INTEGER),
                'certificate' => $this->Certificate,
                'attributes' => $Attributes
            )
        );

        // from ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc
        $ExtendedCertificate = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'extendedCertificateInfo' => $ExtendedCertificateInfo,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature' => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $AttCertVersion = array(
            'type'    => FILE_ASN1_TYPE_INTEGER,
            'mapping' => array('v2')
        );

        $ObjectDigestInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'digestedObjectType' => array(
                                            'type' => FILE_ASN1_TYPE_ENUMERATED,
                                            'children' => array(
                                                              'publicKey',
                                                              'publicKeyCert',
                                                              'otherObjectTypes'
                                                          )
                                            ),
                'otherObjectTypeID' => array(
                                           'type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER,
                                           'optional' => true
                                       ),
                'digestAlgorithm' => $AlgorithmIdentifier,
                'objectDigest' => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $Holder = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'baseCertificateID' => array(
                                           'constant' => 0,
                                           'optional' > true
                                       ) + $IssuerSerial,
                'entityName' => array(
                                    'constant' => 1,
                                    'optional' => true
                                ) + $GeneralNames,
                'objectDigestInfo' => array(
                                          'constant' => 2,
                                          'optional' => true
                                      ) + $ObjectDigestInfo
            )
        );

        $V2Form = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                              'issuerName' => array('optional' => true) + $GeneralNames,
                              'baseCertificateID' => array(
                                                         'constant' => 0,
                                                         'optional' => true
                                                     ) + $IssuerSerial,
                              'objectDigestInfo' => array(
                                                        'constant' => 1,
                                                        'optional' => true
                                                    ) + $ObjectDigestInfo
                          )
        );

        $AttCertIssuer = array(
            'type' => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                              'v1Form' => $GeneralNames,
                              'v2Form' => array(
                                              'constant' => 0,
                                              'optional' => true,
                                          ) + $V2Form
                          )
        );


        $AttributeCertificateInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version' => array(
                                 'optional' => true,
                                 'default' => 'v2'
                             ) + $AttCertVersion,
                'holder' => $Holder,
                'issuer' => $AttCertIssuer,
                'signature' => $AlgorithmIdentifier,
                'serialNumber' => $CertificateSerialNumber,
                'attrCertValidityPeriod' => $AttCertValidityPeriod,
                'attributes' => array(
                                    'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                    'min'      => 0,
                                    'max'      => -1,
                                    'children' => $Attribute
                                ),
                'issuerUniqueID' => array('optional' => true) + $UniqueIdentifier,
                'extensions' => array('optional' => true) + $this->Extensions
            )
        );

        // from https://tools.ietf.org/html/rfc3281
        $AttributeCertificateV2 = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'acinfo' => $AttributeCertificateInfo,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature' => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $AttCertVersionV1 = array(
            'type'    => FILE_ASN1_TYPE_INTEGER,
            'mapping' => array('v1')
        );

        $AttributeCertificateInfoV1 = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version' => array(
                                 'optional' => true,
                                 'default' => 'v1'
                             ) + $AttCertVersionV1,
                'subject' => array(
                                 'type' => FILE_ASN1_TYPE_CHOICE,
                                 'children' => array(
                                                   'baseCertificateID' => array(
                                                       'constant' => 0,
                                                       'optional' > true
                                                   ) + $IssuerSerial,
                                                   'subjectName' => array(
                                                       'constant' => 1,
                                                       'optional' > true
                                                   ) + $GeneralNames
                                               )
                                 ),
                'issuer' => $GeneralNames,
                'signature' => $AlgorithmIdentifier,
                'serialNumber' => $CertificateSerialNumber,
                'attCertValidityPeriod' => $AttCertValidityPeriod,
                'attributes' => array(
                                    'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                    'min'      => 0,
                                    'max'      => -1,
                                    'children' => $Attribute
                                ),
                'issuerUniqueID' => array('optional' => true) + $UniqueIdentifier,
                'extensions' => array('optional' => true) + $this->Extensions
            )
        );

        $AttributeCertificateV1 = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'acInfo' => $AttributeCertificateInfoV1,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature' => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $OtherCertificateFormat = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'otherCertFormat' => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                'otherCert' => array('type' => FILE_ASN1_TYPE_ANY)
            )
        );

        $CertificateChoices = array(
            'type' => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'certificate' => $this->Certificate,
                'extendedCertificate' => array(
                                             //'type' => FILE_ASN1_TYPE_ANY,
                                             'constant' => 0,
                                             'optional' => true,
                                             'implicit' => true
                                         ) + $ExtendedCertificate,
                'v1AttrCert' => array(
                                    //'type' => FILE_ASN1_TYPE_ANY,
                                    'constant' => 1,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $AttributeCertificateV1,
                'v2AttrCert' => array(
                                    //'type' => FILE_ASN1_TYPE_ANY,
                                    'constant' => 2,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $AttributeCertificateV2,
                'other' => array(
                               //'type' => FILE_ASN1_TYPE_ANY,
                               'constant' => 3,
                               'optional' => true,
                               'implicit' => true
                           ) +  $OtherCertificateFormat
            )
        );

        $CertificateSet = array(
            'type' => FILE_ASN1_TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $CertificateChoices
        );

        $OtherRevocationInfoFormat = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'otherRevInfoFormat' => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                'otherRevInfo' => array('type' => FILE_ASN1_TYPE_ANY)
            )
        );

        $RevocationInfoChoice = array(
            'type' => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'crl' => $this->CertificateList,
                'other' => array(
                               'constant' => 1,
                               'optional' => true,
                               'implicit' => true
                           ) + $OtherRevocationInfoFormat
            )
        );

        $RevocationInfoChoices = array(
            'type' => FILE_ASN1_TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $RevocationInfoChoice
        );

        $IssuerAndSerialNumber = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'issuer' => $this->Name,
                'serialNumber' => $CertificateSerialNumber
            )
        );

        $SubjectKeyIdentifier = array('type' => FILE_ASN1_TYPE_OCTET_STRING);

        $SignerIdentifier = array(
            'type' => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'issuerAndSerialNumber' => $IssuerAndSerialNumber,
                'subjectKeyIdentifier' => array(
                                              'constant' => 0,
                                              'optional' => true
                                          ) + $SubjectKeyIdentifier
            )
        );

        $SignedAttributes = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $UnsignedAttributes = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $SignatureAlgorithmIdentifier = $AlgorithmIdentifier;

        $SignatureValue = array('type' => FILE_ASN1_TYPE_OCTET_STRING);

        $SignerInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version' => $CMSVersion,
                'sid' => $SignerIdentifier,
                'digestAlgorithm' => $DigestAlgorithmIdentifier,
                'signedAttrs' => array(
                                     'constant' => 0,
                                     'optional' => true,
                                     'implicit' => true
                                 ) + $SignedAttributes,
                'signatureAlgorithm' => $SignatureAlgorithmIdentifier,
                'signature' => $SignatureValue,
                'unsignedAttrs' => array(
                                       'constant' => 1,
                                       'optional' => true,
                                       'implicit' => true
                                   ) + $UnsignedAttributes
            )
        );

        $SignerInfos = array(
            'type' => FILE_ASN1_TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $SignerInfo
        );

        $this->SignedData = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version' => $CMSVersion,
                'digestAlgorithms' => $DigestAlgorithmIdentifiers,
                'encapContentInfo' => $EncapsulatedContentInfo,
                'certificates' => array(
                                     'constant' => 0,
                                     'optional' => true,
                                     'implicit' => true
                                 ) + $CertificateSet,
                'crls' => array(
                              'constant' => 1,
                              'optional' => true,
                              'implicit' => true
                          ) + $RevocationInfoChoices,
                'signerInfos' => $SignerInfos
            )
        );

        $Hash = array('type' => FILE_ASN1_TYPE_OCTET_STRING);

        $ESSCertID = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'certHash' => $Hash, // sha1 hash of entire cert
                'issuerSerial' => array('optional' => true) + $IssuerSerial
            )
        );

        $PolicyQualifierId = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $PolicyQualifierInfo = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'policyQualifierId' => $PolicyQualifierId,
                'qualifier'         => array('type' => FILE_ASN1_TYPE_ANY)
            )
        );

        $CertPolicyId = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $PolicyInformation = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'policyIdentifier' => $CertPolicyId,
                'policyQualifiers' => array(
                                          'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                          'min'      => 0,
                                          'max'      => -1,
                                          'optional' => true,
                                          'children' => $PolicyQualifierInfo
                                      )
            )
        );

        $this->SigningCertificate = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'certs' => array(
                               'type'     => FILE_ASN1_TYPE_SEQUENCE,
                               'min'      => 1,
                               'max'      => -1,
                               'children' => $ESSCertID
                           ),
                'policies' => array(
                                  'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                  'min'      => 1,
                                  'max'      => -1,
                                  'optional' => true,
                                  'children' => $PolicyInformation
                              )
            )
        );

        $ESSCertIDv2 = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'hashAlgorithm' => array(
                                       'optional' => true,
                                       'default' => array('algorithm' => 'id-sha256', 'parameters' => array('null' => '')),
                                   ) + $AlgorithmIdentifier,
                'certHash' => $Hash,
                'issuerSerial' => array('optional' => true) + $IssuerSerial
            )
        );

        $this->SigningCertificateV2 = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'certs' => array(
                               'type'     => FILE_ASN1_TYPE_SEQUENCE,
                               'min'      => 1,
                               'max'      => -1,
                               'children' => $ESSCertIDv2
                           ),
                'policies' => array(
                                  'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                  'min'      => 1,
                                  'max'      => -1,
                                  'optional' => true,
                                  'children' => $PolicyInformation
                              )
            )
        );

        $this->oids = array(
            '1.2.840.113549.1.7.1' => 'id-data', // https://tools.ietf.org/html/rfc5652#section-4
            '1.2.840.113549.1.7.2' => 'id-signedData', // https://tools.ietf.org/html/rfc5652#section-5
            // the rest are currently unsupported
            '1.2.840.113549.1.7.3' => 'id-envelopedData', // https://tools.ietf.org/html/rfc5652#section-6
            '1.2.840.113549.1.7.5' => 'id-digestedData', // https://tools.ietf.org/html/rfc5652#section-7
            '1.2.840.113549.1.7.6' => 'id-encryptedData', // https://tools.ietf.org/html/rfc5652#section-8
            '1.2.840.113549.1.9.16.1.2' => 'id-ct-authData', // https://tools.ietf.org/html/rfc5652#section-9

            '1.2.840.113549.1.9.3' => 'id-contentType', // https://tools.ietf.org/html/rfc5652#section-11.1
            '1.2.840.113549.1.9.4' => 'id-messageDigest', // https://tools.ietf.org/html/rfc5652#section-11.2
            '1.2.840.113549.1.9.5' => 'id-signingTime', // https://tools.ietf.org/html/rfc5652#section-11.3
            '1.2.840.113549.1.9.6' => 'id-countersignature', // https://tools.ietf.org/html/rfc5652#section-11.4

            '1.2.840.113549.1.9.15' => 'pkcs-9-at-smimeCapabilities', // https://tools.ietf.org/html/rfc2985

            '1.2.840.113549.1.9.16.2.12' => 'id-aa-signingCertificate', // https://tools.ietf.org/html/rfc2634#section-5.4
            '1.2.840.113549.1.9.16.2.47' => 'id-aa-signingCertificateV2', // https://tools.ietf.org/html/rfc5035#section-3

            '1.2.840.113549.1.9.16.2.7' => 'id-aa-contentIdentifier',

            // from RFC5754
            '2.16.840.1.101.3.4.2.4' => 'id-sha224',
            '2.16.840.1.101.3.4.2.1' => 'id-sha256',
            '2.16.840.1.101.3.4.2.2' => 'id-sha384',
            '2.16.840.1.101.3.4.2.3' => 'id-sha512'
        ) + $this->oids;

        $this->baseSignedData = array(
            'contentType' => 'id-signedData',
            'content' => array(
                'version' => 'v1',
                'digestAlgorithms' => array(),
                'encapContentInfo' => array(
                    'eContentType' => 'id-data',
                    'eContent' => ''
                ),
                'certificates' => array(),
                //'crls' => array(),
                'signerInfos' => array()
            )
        );
        $this->baseSignerInfo = array(
            'version' => 'v1',
            'sid' => array(
                'issuerAndSerialNumber' => array(
                    'issuer' => array(),
                    'serialNumber' => new Math_BigInteger()
                )
            ),
            'digestAlgorithm' => array(
                'algorithm' => array()
            ),
            'signedAttrs' => array(),
            'signatureAlgorithm' => array(
                'algorithm' => 'rsaEncryption',
                'parameters' => array('null' => '')
            ),
            'signature' => ''
        );
        $this->currentCMS = $this->baseSignedData;
        $this->keys = array();
    }

    function load($src)
    {
        $this->signatureSubjects = $this->certs = array();

        $asn1 = new File_ASN1();
        $src = $this->_extractBER($src);
        if ($src === false) {
            $this->currentCMS = false;
            return false;
        }

        $asn1->loadOIDs($this->oids);
        $decoded = $asn1->decodeBER($src);
        if (!empty($decoded)) {
            $cms = $asn1->asn1map($decoded[0], $this->ContentInfo);
        }
        if (!isset($cms) || $cms == false) {
            $this->currentCMS = false;
            return false;
        }

        switch ($cms['contentType']) {
            case 'id-signedData':
                $signatureContainer = $cms['content']->element; //substr($src, $decoded[0]['content'][1]['start'], $decoded[0]['content'][1]['length']);
                $decoded = $asn1->decodeBER($cms['content']->element);
                $cms['content'] = $asn1->asn1map($decoded[0], $this->SignedData);
                if (isset($cms['content']['certificates'])) {
                    foreach ($cms['content']['certificates'] as $i => $cert) {
                        if (isset($cert['certificate'])) {
                            $temp = $decoded[0]['content'][3]['content'][$i];
                            $cert = substr($signatureContainer, $temp['start'], $temp['length']);
                            $this->certs[] = $cert;
                        }
                    }
                }
                foreach ($cms['content']['signerInfos'] as $key => &$signerInfo) {
                    /*
                       The result of the message digest calculation process depends on
                       whether the signedAttrs field is present.  When the field is absent,
                       the result is just the message digest of the content as described
                       above.  When the field is present, however, the result is the message
                       digest of the complete DER encoding of the SignedAttrs value
                       contained in the signedAttrs field.
                    */
                    if (isset($signerInfo['signedAttrs']) && count($signerInfo['signedAttrs'])) {
                        $signerInfoIdx = 3 + isset($cms['content']['certificates']) + isset($cms['content']['crls']);
                        $asn1desc = $decoded[0]['content'][$signerInfoIdx]['content'][$key]['content'][3];
                        /*
                           The IMPLICIT [0] tag in the signedAttrs is not used for the DER
                           encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
                           encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
                           tag, MUST be included in the message digest calculation along with
                           the length and content octets of the SignedAttributes value.
                        */
                        $temp = substr($signatureContainer, $asn1desc['start'], $asn1desc['length']);
                        $temp[0] = chr(FILE_ASN1_TYPE_SET | 0x20);
                        //$temp = chr((FILE_ASN1_CLASS_CONTEXT_SPECIFIC << 6) | 0x20) . ASN1::_encodeLength(strlen($temp)) . $temp;
                        $this->signatureSubjects[] = $temp;
                        
                        foreach ($signerInfo['signedAttrs'] as &$attr) {
                            switch ($attr['type']) {
                                case 'id-aa-signingCertificate':
                                    foreach ($attr['value'] as &$value) {
                                        $temp = $asn1->decodeBER($value->element);
                                        $value = $asn1->asn1map($temp[0], $this->SigningCertificate);
                                    }
                                    break;
                                case 'id-aa-signingCertificateV2':
                                    foreach ($attr['value'] as &$value) {
                                        $temp = $asn1->decodeBER($value->element);
                                        $value = $asn1->asn1map($temp[0], $this->SigningCertificateV2);
                                    }
                            }
                        }
                    }
                }
                
                $this->currentCMS = $cms;
                $this->keys = array();
                
                return $cms;
        }
    }

    function getCerts()
    {
        return $this->certs;
    }

    function _getSubjectPublicKey($cert)
    {
        if (!isset($cert['tbsCertificate']['extensions'])) {
            return false;
        }
        foreach ($cert['tbsCertificate']['extensions'] as $ext) {
            if ($ext['extnId'] == 'id-ce-subjectKeyIdentifier') {
                return $ext['extnValue'];
            }
        }
        return false;
    }

    /**
     * Validate a signature
     *
     * Returns true if the signature is verified or a false if it isn't.
     *
     * The behavior of this function is inspired by {@link http://php.net/openssl-verify openssl_verify}.
     *
     * @access public
     * @return Boolean
     */
    function validateSignature()
    {
        if (!is_array($this->currentCMS) || !isset($this->signatureSubjects)) {
            return null;
        }

        $matches = 0;
        $this->signingCerts = array();
        foreach ($this->currentCMS['content']['signerInfos'] as $i => $signerInfo) {
            foreach ($signerInfo['signedAttrs'] as $attr) {
                switch ($attr['type']) {
                    case 'id-messageDigest':
                        $hash = new Crypt_Hash(preg_replace('#^id-#', '', $signerInfo['digestAlgorithm']['algorithm']));
                        $messageDigest = $hash->hash(base64_decode($this->currentCMS['content']['encapContentInfo']['eContent']));
                        $expectedHash = base64_decode($attr['value'][0]['octetString']);
                        if ($messageDigest != $expectedHash) {
                            return false;
                        }
                        break 2;
                }
            }

            /*
              The recipient MAY obtain the correct public key for the signer
              by any means, but the preferred method is from a certificate obtained
              from the SignedData certificates field.
            */
            foreach ($this->currentCMS['content']['certificates'] as $j => $cert) {
                switch (true) {
                    case isset($cert['certificate']):
                        $issuer = $cert['certificate']['tbsCertificate']['issuer'];
                        $sn = $cert['certificate']['tbsCertificate']['serialNumber'];
                        $key = $cert['certificate']['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
                        $keyid = $this->_getSubjectPublicKey($cert['certificate']);
                        break;
                    case isset($cert['extendedCertificate']):
                        //$issuer = $cert['extendedCertificate']['certificate']['tbsCertificate']['issuer'];
                        //$sn = $cert['extendedCertificate']['certificate']['tbsCertificate']['serialNumber'];
                        //$key = $cert['extendedCertificate']['certificate']['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
                        //$keyid = $this->_getSubjectPublicKey($cert['extendedCertificate']['certificate']);
                        //break;
                    case isset($cert['v1AttrCert']):
                        // ['v1AttrCert']['acInfo'] = $AttributeCertificateInfoV1 ?
                    case isset($cert['v2AttrCert']):
                        // ['v2AttrCert']['acInfo'] = $AttributeCertificateInfo ?
                    case isset($cert['other']):
                        // ['other']['otherCert'] = ???
                        continue 2;
                }

                if (isset($signerInfo['sid']['issuerAndSerialNumber'])) {
                    switch (true) {
                        case $issuer != $signerInfo['sid']['issuerAndSerialNumber']['issuer']:
                        case !$sn->equals($signerInfo['sid']['issuerAndSerialNumber']['serialNumber']):
                        case isset($signerInfo['sid']['subjectKeyIdentifier']) && $keyid !== $signerInfo['sid']['subjectKeyIdentifier']:
                            continue 2;
                    }

                    $this->signingCerts[] = $this->certs[$j];

                    switch ($signerInfo['signatureAlgorithm']['algorithm']) {
                        case 'rsaEncryption':
                        case 'md2WithRSAEncryption':
                        case 'md5WithRSAEncryption':
                        case 'sha1WithRSAEncryption':
                        case 'sha224WithRSAEncryption':
                        case 'sha256WithRSAEncryption':
                        case 'sha384WithRSAEncryption':
                        case 'sha512WithRSAEncryption':
                            $rsa = new Crypt_RSA();
                            $rsa->loadKey(substr(base64_decode($key), 1));
                            $rsa->setHash(preg_replace('#^id-#', '', $signerInfo['digestAlgorithm']['algorithm']));
                            $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
                            if ($rsa->verify($this->signatureSubjects[$i], base64_decode($signerInfo['signature']))) {
                                $matches++;
                                break 2;
                            }
                    }
                }
            }
        }

        return count($this->currentCMS['content']['signerInfos']) == $matches;
    }

    function validateESSSignature()
    {
        if (!is_array($this->currentCMS) || !isset($this->signatureSubjects)) {
            return null;
        }

        $matches = 0;
        $this->essSigningCerts = array();

        foreach ($this->currentCMS['content']['signerInfos'] as $i => $signerInfo) {
            unset($hash, $expectedHash, $expectedIssuer, $expectedSN);
            foreach ($signerInfo['signedAttrs'] as $attr) {
                switch ($attr['type']) {
                    case 'id-aa-signingCertificate':
                    case 'id-aa-signingCertificateV2':
                        $hash = $attr['type'] == 'id-aa-signingCertificateV2' ?
                            preg_replace('#^id-#', '', $attr['value'][0]['certs'][0]['hashAlgorithm']['algorithm']) :
                            'sha1';
                        $hash = new Crypt_Hash($hash);
                        $expectedHash = base64_decode($attr['value'][0]['certs'][0]['certHash']);
                        if (isset($attr['value'][0]['certs'][0]['issuerSerial'])) {
                            $expectedIssuer = $attr['value'][0]['certs'][0]['issuerSerial']['issuer'][0]['directoryName'];
                            $expectedSN = $attr['value'][0]['certs'][0]['issuerSerial']['serialNumber'];
                        }
                        break;
                    case 'id-messageDigest':
                        $temp = new Crypt_Hash(preg_replace('#^id-#', '', $signerInfo['digestAlgorithm']['algorithm']));
                        $messageDigest = $temp->hash(base64_decode($this->currentCMS['content']['encapContentInfo']['eContent']));
                        $expectedHash = base64_decode($attr['value'][0]['octetString']);
                        if ($messageDigest != $expectedHash) {
                            return false;
                        }
                }
            }
            if (!isset($hash)) {
                return false;
            }

            foreach ($this->currentCMS['content']['certificates'] as $j => $cert) {
                switch (true) {
                    case isset($cert['certificate']):
                        $issuer = $cert['certificate']['tbsCertificate']['issuer'];
                        $sn = $cert['certificate']['tbsCertificate']['serialNumber'];
                        $key = $cert['certificate']['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
                        break;
                    case isset($cert['extendedCertificate']):
                        //$subject = $cert['extendedCertificate']['certificate']['tbsCertificate']['issuer'];
                        //$sn = $cert['extendedCertificate']['certificate']['tbsCertificate']['serialNumber'];
                        //$key = $cert['extendedCertificate']['certificate']['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
                        //break;
                    case isset($cert['v1AttrCert']):
                        // ['v1AttrCert']['acInfo'] = $AttributeCertificateInfoV1 ?
                    case isset($cert['v2AttrCert']):
                        // ['v2AttrCert']['acInfo'] = $AttributeCertificateInfo ?
                    case isset($cert['other']):
                        // ['other']['otherCert'] = ???
                        continue 2;
                }

                switch (true) {
                    case $hash->hash($this->certs[$j]) != $expectedHash:
                    case isset($expectedIssuer) && $expectedIssuer != $issuer:
                    case isset($expectedSN) && !$expectedSN->equals($sn):
                        continue 2;
                }

                $this->essSigningCerts[] = $this->certs[$j];

                switch ($signerInfo['signatureAlgorithm']['algorithm']) {
                    case 'rsaEncryption':
                    case 'md2WithRSAEncryption':
                    case 'md5WithRSAEncryption':
                    case 'sha1WithRSAEncryption':
                    case 'sha224WithRSAEncryption':
                    case 'sha256WithRSAEncryption':
                    case 'sha384WithRSAEncryption':
                    case 'sha512WithRSAEncryption':
                        $rsa = new Crypt_RSA();
                        $rsa->loadKey(substr(base64_decode($key), 1));
                        $rsa->setHash(preg_replace('#^id-#', '', $signerInfo['digestAlgorithm']['algorithm']));
                        $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
                        if ($rsa->verify($this->signatureSubjects[$i], base64_decode($signerInfo['signature']))) {
                            $matches++;
                            break 2;
                        }
                }
            }
        }

        return count($this->currentCMS['content']['signerInfos']) == $matches;
    }

    function hasESSSignature()
    {

        foreach ($this->currentCMS['content']['signerInfos'] as $signerInfo) {
            $exists = false;
            foreach ($signerInfo['signedAttrs'] as $attr) {
                switch ($attr['type']) {
                    case 'id-aa-signingCertificate':
                    case 'id-aa-signingCertificateV2':
                        $exists = true;
                        break 2;
                }
            }
            if (!$exists) {
                return false;
            }
        }
        return true;
    }

    function getSigningCerts()
    {
        if (empty($this->signingCerts)) {
            $this->validateSignature();
        }
        return $this->signingCerts;
    }

    function getESSSigningCerts()
    {
        if (empty($this->essSigningCerts)) {
            $this->validateESSSignature();
        }
        return $this->essSigningCerts;
    }

    function setHash($hash)
    {
        $this->hash = $hash;
    }

    function removeCerts()
    {
        $this->currentCMS['content']['certificates'] = $this->certs = array();
    }

    function removeSigners()
    {
        $this->currentCMS['content']['signerInfos'] = $this->signatureSubjects = array();
    }

    function removeSigner($x)
    {
        unset($this->currentCMS['content']['signerInfos'][$x], $this->signatureSubjects[$x]);
        $this->currentCMS['content']['signerInfos'] = array_values($this->currentCMS['content']['signerInfos']);
        $this->signatureSubjects = array_values($this->signatureSubjects);
    }

    function removeCert($x)
    {
        unset($this->currentCMS['content']['certificates'][$x], $this->certs[$x]);
        $this->currentCMS['content']['certificates'] = array_values($this->currentCMS['content']['certificates']);
        $this->certs = array_values($this->certs);
    }

    function getSigners()
    {
        $signers = array();
        foreach ($this->currentCMS['content']['signerInfos'] as $signerInfo) {
            $signers[] = $signerInfo['sid'];
        }
        return $signers;
    }

    function getSignerInfos()
    {
        return $this->currentCMS['content']['signerInfos'];
    }

    function setData($data)
    {
        $this->currentCMS['content']['encapContentInfo']['eContent'] = base64_encode($data);
    }

    function getData()
    {
        echo base64_decode($this->currentCMS['content']['encapContentInfo']['eContent']);
    }

    // the X509 cert needs to be a string; the privatekey needs to be a Crypt_RSA object
    function addSigner($x509, $privatekey, $contentID = null)
    {
        $this->keys[] = $privatekey;
        if (!$this->addCert($x509)) {
            return false;
        }
        $cert = new File_X509();
        if (!($result = $cert->loadX509($x509))) {
            return false;
        }
        $digestAlgorithm = array(
            'algorithm' => 'id-' . $this->hash,
            'parameters' => array('null' => '')
        );
        $hash = new Crypt_Hash($this->hash);
        $messageDigest = $hash->hash(base64_decode($this->currentCMS['content']['encapContentInfo']['eContent']));
        $this->currentCMS['content']['digestAlgorithms'][] = $digestAlgorithm;
        $signerInfo = $this->baseSignerInfo;
        $signerInfo['sid']['issuerAndSerialNumber']['issuer'] = $result['tbsCertificate']['issuer'];
        $signerInfo['sid']['issuerAndSerialNumber']['serialNumber'] = $result['tbsCertificate']['serialNumber'];
        $signerInfo['digestAlgorithm'] = $digestAlgorithm;
        $signerInfo['signedAttrs'][] = array(
            'type' => 'id-contentType',
            'value' => array(array(
                           'objectIdentifier' => 'id-data'
                       ))
        );
        $signerInfo['signedAttrs'][] = array(
            'type' => 'id-messageDigest',
            'value' => array(array(
                           'octetString' => base64_encode($messageDigest)
                       ))
        );
        $signerInfo['signedAttrs'][] = array(
            'type' => 'id-aa-signingCertificateV2',
            'value' => array(array(
                           'certs' => array(array(
                                          'hashAlgorithm' => array('algorithm' => 'id-' . $this->hash, 'parameters' => array('null' => '')),
                                          'certHash' => base64_encode($hash->hash($this->_extractBER($x509))),
                                          'issuerSerial' => array(
                                              'issuer' => array(array('directoryName' => $result['tbsCertificate']['issuer'])),
                                              'serialNumber' => $result['tbsCertificate']['serialNumber']
                                          )
                                      ))
                       ))
        );
        $signerInfo['signedAttrs'][] = array(
            'type' => 'id-signingTime',
            'value' => array($this->_timeField('now'))
        );
        if (isset($contentID)) {
            $signerInfo['signedAttrs'][] = array(
                'type' => 'id-aa-contentIdentifier',
                'value' => array(array(
                               'octetString' => base64_encode($contentID)
                           ))
            );
        }

        $asn1 = new File_ASN1();
        $asn1->loadOIDs($this->oids);

        // the 2 in $signerInfo['signedAttrs'][2]['value'][0] in the next few lines corresponds to the
        // location of the id-aa-signingCertificateV2 attribute
        $temp = $signerInfo['signedAttrs'][2]['value'][0];

        $encoded = $asn1->encodeDER($signerInfo['signedAttrs'][2]['value'][0], $this->SigningCertificateV2);
        $signerInfo['signedAttrs'][2]['value'][0] = new File_ASN1_Element($encoded);

        $map = $this->SignedData['children']['signerInfos']['children']['children']['signedAttrs'];
        $encoded = $asn1->encodeDER($signerInfo['signedAttrs'], $map);
        $encoded[0] = chr(FILE_ASN1_TYPE_SET | 0x20);
        $this->signatureSubjects[] = $encoded;
        $privatekey->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        $privatekey->setHash($this->hash);
        $signerInfo['signature'] = base64_encode($privatekey->sign($encoded));

        $signerInfo['signedAttrs'][2]['value'][0] = $temp;
        $this->currentCMS['content']['signerInfos'][] = $signerInfo;

        return true;
    }

    function addCert($x509)
    {
        $x509 = $this->_extractBER($x509);
        if ($x509 === false) {
            return false;
        }
        $this->certs[] = $x509;
        /*
        $cert = new File_X509();
        $result = $cert->loadX509($x509);
        if (!$result) {
            return false;
        }
        */
        $asn1 = new File_ASN1();
        $asn1->loadOIDs($this->oids);
        $result = $asn1->decodeBER($x509);
        if (!$result) {
            return false;
        }
        $result = $asn1->asn1map($result[0], $this->Certificate);
        if (!$result) {
            return false;
        }
        $this->currentCMS['content']['certificates'][] = array('certificate' => new File_ASN1_Element($x509));
        return true;
    }

    function save()
    {
        $cms = $this->currentCMS;
        foreach ($cms['content']['signerInfos'] as $key => &$signerInfo) {
            if (isset($signerInfo['signedAttrs']) && count($signerInfo['signedAttrs'])) {
                $temp = $this->signatureSubjects[$key];
                $temp[0] = chr(FILE_ASN1_CLASS_CONTEXT_SPECIFIC | 0x20);
                $signerInfo['signedAttrs'] = new File_ASN1_Element($temp);
            }
        }
        foreach ($cms['content']['certificates'] as $key => &$cert) {
            if (isset($cert['certificate'])) {
                $cert = new File_ASN1_Element($this->certs[$key]);
            }
        }
        $asn1 = new File_ASN1();
        $asn1->loadOIDs($this->oids);
        $encoded = $asn1->encodeDER($cms['content'], $this->SignedData);
        $cms['content'] = new File_ASN1_Element($encoded);
        return $asn1->encodeDER($cms, $this->ContentInfo);
    }
}
