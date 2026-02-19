<?php
/**
 * Pure-PHP CMS / EnvelopedData Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / EnvelopedData files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\Random;
use phpseclib4\Crypt\AES;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\TripleDES;
use phpseclib4\Exception\BadDecryptionException;
use phpseclib4\Exception\InsufficientSetupException;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Maps\RSAPublicKey;
use phpseclib4\File\ASN1\Types\Choice;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\CMS;
use phpseclib4\File\CMS\EnvelopedData\KeyTransRecipient;
use phpseclib4\File\CMS\EnvelopedData\KeyAgreeRecipient;
use phpseclib4\File\CMS\EnvelopedData\KeyAgreeRecipient\EncryptedKey;
use phpseclib4\File\CMS\EnvelopedData\KEKRecipient;
use phpseclib4\File\CMS\EnvelopedData\PasswordRecipient;
use phpseclib4\File\CMS\EnvelopedData\OtherRecipient;
use phpseclib4\File\CMS\EnvelopedData\Recipient;
use phpseclib4\File\CRL;
use phpseclib4\File\X509;

/**
 * Pure-PHP CMS / EnvelopedData Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class EnvelopedData implements \ArrayAccess, \Countable, \Iterator
{
    use \phpseclib4\Crypt\Common\Traits\ASN1AlgorithmIdentifier;

    private Constructed|array $cms;
    private static bool $binary = false;
    public string $cek; // content encryption key

    public function __construct(string $data, string $encryptionAlgorithm = 'aes128-CBC-PAD', #[\SensitiveParameter] ?string $key = null)
    {
        $cipher = self::getPBES2EncryptionObject($encryptionAlgorithm);
        $keyLength = $cipher->getKeyLength() >> 3;
        if (isset($key) && strlen($key) != $keyLength) {
            throw new LengthException('key is ' . strlen($key) . " bytes long; it should be $keyLength bytes long");
        }
        $this->cek = $key ?? Random::string($keyLength);
        $cipher->setKey($this->cek);
        $iv = Random::string($cipher->getBlockLengthInBytes());
        $cipher->setIV($iv);
        $encrypted = $cipher->encrypt($data);
        $this->cms = [
            'contentType' => 'id-envelopedData',
            'content' => [
                'version' => 'v0',
                // at *least* one recipientInfo is required, so we'll include a dummy one
                'recipientInfos' => [[
                    'ori' => ['oriType' => '0.0', 'oriValue' => ''],
                ]],
                'encryptedContentInfo' => [
                    'contentType' => 'id-data',
                    'contentEncryptionAlgorithm' => [
                        'algorithm' => $encryptionAlgorithm,
                        'parameters' => new OctetString($iv),
                    ],
                    'encryptedContent' => $encrypted,
                ]
            ]
        ];
        $this->calculateVersion();
    }

    // CMS::load() takes care of the PEM / DER encoding toggling
    // if you want to load an array or Constructed as a SignedData instance you'll
    // need to call CMS\SignedData::load()
    public static function load(string|array|Constructed $encoded): self
    {
        ASN1::loadOIDs('CMS');

        $r = new \ReflectionClass(__CLASS__);
        $cms = $r->newInstanceWithoutConstructor();
        $cms->cms = is_string($encoded) ? self::loadString($encoded) : $encoded;

        ASN1::disableCacheInvalidation();
        foreach ($cms->cms['content']['recipientInfos'] as $i => $recipient) {
            $recipient = &$cms->cms['content']['recipientInfos'][$i];
            $key = $recipient->index;
            if ($recipient instanceof Choice) {
                $encoded = chr(ASN1::TYPE_SEQUENCE | 0x20) . substr($recipient->value->getEncoded(), 1);
                $recipient[$key] = match ($key) {
                    'ktri' => KeyTransRecipient::load($encoded),
                    'kari' => KeyAgreeRecipient::load($encoded),
                    'kekri' => KEKRecipient::load($encoded),
                    'pwri' => PasswordRecipient::load($encoded),
                    //'ori' => OtherRecipient::load($recipient),
                    default => $recipient->value,
                };
                if (!$recipient[$key] instanceof Constructed) {
                    $recipient[$key]->parent = $recipient;
                    $recipient[$key]->depth = $recipient->depth + 1;
                    $recipient[$key]->key = $key;
                }
            } elseif (is_array($recipient)) {
                $key = key($recipient);
                $value = current($recipient);
                $recipient[$key] = match ($key) {
                    'ktri' => new KeyTransRecipient($value),
                    'kari' => new KeyAgreeRecipient($value),
                    'kekri' => new KEKRecipient($value),
                    'pwri' => new PasswordRecipient($value),
                    default => $value,
                };
            }
            if (!$recipient[$key] instanceof Constructed) {
                $recipient[$key]->cms = $cms;
                if ($recipient[$key] instanceof KeyAgreeRecipient) {
                    $encryptedKeys = &$recipient[$key]['recipientEncryptedKeys'];
                    for ($i = 0; $i < count($encryptedKeys); $i++) {
                        $encryptedKeys[$i]->cms = $cms;
                        $encryptedKeys[$i]->recipient = $recipient[$key];
                    }
                    unset($encryptedKeys);
               }
            }
            unset($recipient);
        }
        ASN1::enableCacheInvalidation();

        return $cms;
    }

    private static function loadString(string $encoded): Constructed
    {
        $decoded = ASN1::decodeBER($encoded);
        $cms = ASN1::map($decoded, Maps\ContentInfo::MAP);
        ASN1::disableCacheInvalidation();
        $rules = [];
        $rules['originatorInfo']['certs'] = [CMS::class, 'mapInCerts'];
        $rules['originatorInfo']['crls'] = [CMS::class, 'mapInCRLs'];
        $decoded = ASN1::decodeBER($cms['content']->value);
        $cms['content'] = ASN1::map($decoded, Maps\EnvelopedData::MAP, $rules);
        $cms['content']->parent = $cms;
        $cms['content']->key = 'content';
        ASN1::enableCacheInvalidation();
        return $cms;
    }

    private function calculateVersion(): void
    {
        // based on https://www.rfc-editor.org/rfc/rfc5652#page-19
        $this->compile();
        if (isset($this->cms['content']['originatorInfo'])) {
            foreach ($this->cms['content']['originatorInfo']['certs'] as $cert) {
                if (isset($cert['other'])) {
                    $this->cms['content']['version'] = 'v4';
                    return;
                }
            }
            foreach ($this->cms['content']['originatorInfo']['crls'] as $crl) {
                if (isset($crl['other'])) {
                    $this->cms['content']['version'] = 'v4';
                    return;
                }
            }
            foreach ($this->cms['content']['originatorInfo']['certs'] as $cert) {
                if (isset($cert['v2AttrCert'])) {
                    $this->cms['content']['version'] = 'v3';
                    return;
                }
            }
        }
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            if (isset($recipient['pwri']) || isset($recipient['ori'])) {
                $this->cms['content']['version'] = 'v3';
                return;
            }
        }
        if (isset($this->cms['content']['originatorInfo']) || isset($this->cms['content']['unprotectedAttrs'])) {
            $this->cms['content']['version'] = 'v2';
            return;
        }
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            if ($recipient->value['version'] != 'v0') {
                $this->cms['content']['version'] = 'v2';
                return;
            }
        }
        $this->cms['content']['version'] = 'v0';
    }

    /** @return Recipient[] */
    public function getRecipients(): array
    {
        $this->compile();
        $result = [];
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            $result[] = $recipient->value;
        }
        return $result;
    }

    // returns all recipients matching $keyIdentifier
    /** @return (KEKRecipient|KeyTransRecipient|EncryptedKey)[] */
    public function findRecipients(string|X509 $keyIdentifier): array
    {
        $this->compile();
        $recipients = [];
        if (is_string($keyIdentifier)) {
            foreach ($this->cms['content']['recipientInfos'] as $recipient) {
                if (isset($recipient['kekri']) && $recipient['kekri']['kekid']['keyIdentifier'] == $keyIdentifier) {
                    $recipients[] = $recipient['kekri'];
                }
            }
            return $recipients;
        }
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            switch ($recipient->index) {
                case 'ktri':
                    if ($recipient->value->matchesX509($keyIdentifier)) {
                        $recipients[] = $recipient['ktri'];
                    }
                    break;
                case 'kari':
                    foreach ($recipient->value->getEncryptedKeys() as $key) {
                        if ($key->matchesX509($keyIdentifier)) {
                            $recipients[] = $key;
                        }
                    }
            }
        }
        return $recipients;
    }

    // return the first recipient matching $keyIdentifier or null if none are found
    public function findRecipient(string|X509 $keyIdentifier): KEKRecipient|KeyTransRecipient|EncryptedKey|null
    {
        $recipients = $this->findRecipients($keyIdentifier);
        return count($recipients) ? $recipients[0] : null;
    }

    /** @return PasswordRecipient[] */
    public function getPasswordRecipients(): array
    {
        $this->compile();
        $result = [];
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            if (isset($recipient['pwri'])) {
                $result[] = $recipient['pwri'];
            }
        }
        return $result;
    }

    /** @return (KEKRecipient|KeyTransRecipient|EncryptedKey)[] */
    public function getKeyRecipients(): array
    {
        $this->compile();
        $result = [];
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            switch ($recipient->index) {
                case 'kekri':
                case 'ktri':
                    $result[] = $recipient->value;
                    break;
                case 'kari':
                    foreach ($recipient->value->getEncryptedKeys() as $key) {
                        $result[] = $key;
                    }
            }
        }
        return $result;
    }

    public function decryptWithKey(#[\SensitiveParameter] string|EC\PrivateKey|RSA\PrivateKey $key): string
    {
        $this->compile();
        foreach ($this->cms['content']['recipientInfos'] as $recipient) {
            switch (true) {
                case isset($recipient['kekri']) && is_string($key):
                    try {
                        return $recipient['kekri']->withKey($key)->decrypt();
                    } catch (\Exception $e) {
                    }
                    break;
                case isset($recipient['ktri']) && $key instanceof RSA\PrivateKey:
                    try {
                        return $recipient['ktri']->withKey($key)->decrypt();
                    } catch (\Exception $e) {
                    }
                    break;
                case isset($recipient['kari']) && $key instanceof EC\PrivateKey:
                    foreach ($recipient['kari']->getEncryptedKeys() as $key) {
                        try {
                            return $key->withKey($key)->decrypt();
                        } catch (\Exception $e) {
                        }
                    }
            }
        }
        throw new BadDecryptionException('Unable to perform decryption with key');
    }

    public function decryptWithPassword(#[\SensitiveParameter] string $password): string
    {
        $recipients = $this->getPasswordRecipients();
        foreach ($recipients as $recipient) {
            try {
                return $recipient->withPassword($password)->decrypt();
            } catch (\Exception $e) {
            }
        }
        throw new BadDecryptionException('Unable to perform decryption with password');
    }

    public function createNewRecipientFromPassword(#[\SensitiveParameter] string $password, string $encryptionAlgorithm = 'aes128-CBC-PAD'): PasswordRecipient
    {
        // to decrypt with openssl cli do this:
        // openssl cms -decrypt -inform PEM -in enveloped.pem -out plaintext.txt -pwri_password 'password'

        if (!isset($this->cek)) {
            throw new InsufficientSetupException('A content encryption key is unavailable');
        }
        $params = [
            'encryptionAlgorithm' => 'id-PBES2',
            'encryptionScheme' => $encryptionAlgorithm,
        ];
        $keyCipher = self::getCryptoObjectFromParams($password, $params);
        $keyCipher->disablePadding();
        $keyCipher->enableContinuousBuffer();
        $params = $keyCipher->getMetaData('algorithmIdentifier')['parameters'];
        $decoded = ASN1::decodeBER($params->value);
        $params = ASN1::map($decoded, Maps\PBES2params::MAP);
        $kdf = $params['keyDerivationFunc'];
        $kea = ['algorithm' => 'id-alg-PWRI-KEK', 'parameters' => $params['encryptionScheme']];

        // see https://datatracker.ietf.org/doc/html/rfc3211
        $keyCheck = ~substr($this->cek, 0, 3);
        $contentCipher = self::getPBES2EncryptionObject((string) $this->cms['content']['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm']);
        $padding = Random::string(max($keyCipher->getBlockLengthInBytes(), 2 * $contentCipher->getBlockLengthInBytes()) - strlen($this->cek) - 4);
        $cekBlock = chr(strlen($this->cek)) . $keyCheck . $this->cek . $padding;

        $encryptedKey = $keyCipher->encrypt($cekBlock);
        $encryptedKey = $keyCipher->encrypt($encryptedKey);

        $recipient = [
            'version' => 'v0', // Always set to 0
            // "If [keyDerivationAlgorithm] is absent, the key-encryption key is supplied from an external
            //  source, for example a hardware crypto token such as a smart card."
            'keyDerivationAlgorithm' => $kdf,
            'keyEncryptionAlgorithm' => $kea,
            'encryptedKey' => $encryptedKey,
        ];
        $recipient = new PasswordRecipient($recipient);

        $this->placeRecipient($recipient, 'pwri');
        $this->deletePlaceHolder();
        $this->calculateVersion();

        return $recipient;
    }

    public function createNewRecipientFromKeyWithIdentifier(string $key, string $identifier, ?\DateTimeInterface $date = null): KEKRecipient
    {
        // to decrypt with openssl cli do this:
        // openssl cms -decrypt -in enveloped.pem -secretkey <hex-kek> -secretkeyid <hex-key-id> -out plaintext.txt

        if (!isset($this->cek)) {
            throw new InsufficientSetupException('A content encryption key is unavailable');
        }

        $keyLength = strlen($key);
        if (!in_array($keyLength, [16, 24, 32])) {
            throw new LengthException('Key length must be 16, 24, 32');
        }

        $kekid = ['keyIdentifier' => $identifier];
        if (isset($date)) {
            $kekid['date'] = $date;
        }

        $recipient = [
            'version' => 'v4', // always set to 4
            'kekid' => $kekid,
            'keyEncryptionAlgorithm' => ['algorithm' => 'id-aes' . ($keyLength << 3) . '-wrap'],
            'encryptedKey' => self::wrapAES($key, $this->cek),
        ];
        $recipient = new KEKRecipient($recipient);

        $this->placeRecipient($recipient, 'kekri');
        $this->deletePlaceHolder();
        $this->calculateVersion();

        return $recipient;
    }

    public function createNewRecipientFromX509(X509 $x509, int $type = CMS::ISSUER_AND_DN): Recipient
    {
        $publicKey = $x509->getPublicKey();
        if (!$publicKey instanceof RSA && !$publicKey instanceof EC) {
            throw new UnexpectedValueException('Public key must be RSA or EC');
        }
        if ($publicKey instanceof RSA) {
            // to decrypt with openssl do this:
            // openssl cms -decrypt -inform PEM -in enveloped.pem -out plaintext.txt -recip recipient.crt -inkey recipient.key"

            if (!($publicKey->getPadding() & RSA::ENCRYPTION_OAEP)) {
                $algorithm = ['algorithm' => 'rsaEncryption', 'parameters' => new ASN1\Types\ExplicitNull()];
            } else {
                $hash = (string) $publicKey->getHash();
                if (substr($hash, 0, 3) == 'sha') {
                    $hash = "id-$hash";
                }
                $mgfHash = (string) $publicKey->getMGFHash();
                if (substr($mgfHash, 0, 3) == 'sha') {
                    $mgfHash = "id-$mgfHash";
                }
                $algorithm = [
                    'algorithm' => 'id-RSAES-OAEP',
                    'parameters' => [
                        'hashAlgorithm' => ['algorithm' => $hash],
                        'maskGenAlgorithm' => [
                            'algorithm' => 'id-mgf1',
                            'parameters' => ['algorithm' => $mgfHash],
                        ],
                        'pSourceAlgorithm' => ['algorithm' => 'id-pSpecified', 'parameters' => new OctetString($publicKey->getLabel())],
                    ]
                ];
                $mgf = &$algorithm['parameters']['maskGenAlgorithm']['parameters'];
                $mgf = new Element(ASN1::encodeDER($mgf, Maps\AlgorithmIdentifier::MAP));
                $algorithm['parameters'] = new Element(ASN1::encodeDER($algorithm['parameters'], Maps\RSAES_OAEP_params::MAP));
            }
            $recipient = [
                // version is the syntax version number.  If the RecipientIdentifier
                // is the CHOICE issuerAndSerialNumber, then the version MUST be 0.
                // If the RecipientIdentifier is subjectKeyIdentifier, then the
                // version MUST be 2.
                'version' => $type == CMS::ISSUER_AND_DN ? 'v0' : 'v2',
                'rid' => CMS::createSIDRID($x509, $type),
                'keyEncryptionAlgorithm' => $algorithm,
                'encryptedKey' => $publicKey->encrypt($this->cek),
            ];
            $recipient = new KeyTransRecipient($recipient);
            $this->placeRecipient($recipient, 'ktri');
        } else {
            $privateKey = EC::createKey($publicKey->getCurve());
            $secret = \phpseclib4\Crypt\DH::computeSecret($privateKey, $publicKey);
            $parameters = new ASN1\Element(ASN1::encodeDER(['algorithm' => 'id-aes128-wrap'], Maps\AlgorithmIdentifier::MAP));
            $sharedInfo = [
                'keyInfo' => $parameters,
                'suppPubInfo' => pack('N', 128)
            ];
            $sharedInfo = ASN1::encodeDER($sharedInfo, Maps\ECCCMSSharedInfo::MAP);
            $hash = $publicKey->getHash();
            $kek = self::ANSIX963KDF($secret, 16, $sharedInfo, $hash);
            $recipient = [
                'version' => 'v3', // always set to v3
                'originator' => ['originatorKey' => new Element($privateKey->getPublicKey()->toString('PKCS8', ['binary' => true]))],
                'keyEncryptionAlgorithm' => ['algorithm' => 'dhSinglePass-stdDH-' . $hash . 'kdf-scheme', 'parameters' => $parameters],
                'recipientEncryptedKeys' => [['rid' => CMS::createSIDRID($x509, $type), 'encryptedKey' => self::wrapAES($kek, $this->cek)]],
            ];
            $recipient = new KeyAgreeRecipient($recipient);
            $this->placeRecipient($recipient, 'kari');
        }

        $this->deletePlaceHolder();
        $this->calculateVersion();

        return $recipient;
    }

    public function placeRecipient(Recipient $recipient, string $type): void
    {
        $this->compile();
        $recipients = &$this->cms['content']['recipientInfos'];
        $idx = count($recipients);
        $recipient->compile();
        $recipients[$idx] = new Choice($type, $recipient);
        $recipient->cms = $this;
        $recipients[$idx]->parent = $recipients;
        $recipients[$idx]->key = $idx;
        $recipients[$idx]->depth = $recipients->depth;
        $recipient->parent = $recipients[$idx];
        $recipient->depth = $recipients[$idx]->depth + 1;
        $recipients[$idx][$type] = $recipient;
    }

    public function deletePlaceHolder(): void
    {
        foreach ($this->cms['content']['recipientInfos'] as $i => $recipient) {
            switch (true) {
                case !isset($recipient['ori']):
                case $recipient['ori']['oriType'] != '0.0':
                case $recipient['ori']['oriValue'] != '':
                    continue 2;
            }
            unset($this->cms['content']['recipientInfos'][$i]);
        }
    }

    public function wrapAES(#[\SensitiveParameter] string $kek, #[\SensitiveParameter] string $cek): string
    {
        $p = str_split($cek, 8);
        $n = count($p);
        // from https://datatracker.ietf.org/doc/html/rfc3394.html#section-2.2.3.1
        $iv = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6";

        $aes = new AES('ecb');
        $aes->setKey($kek);
        $aes->disablePadding();

        // 1) Initialize variables.
        $a = $iv;
        $r = $p;

        // 2) Calculate intermediate values.
        for ($j = 0; $j <= 5; $j++) {
            for ($i = 0; $i < $n; $i++) {
                $b = $aes->encrypt($a . $r[$i]);
                $t = pack('J', $n * $j + $i + 1);
                $a = substr($b, 0, 8) ^ $t;
                $r[$i] = substr($b, 8);
            }
        }

        // 3) Output the results.
        return $a . implode('', $r);
    }

    // from https://www.rfc-editor.org/rfc/rfc3217#section-3.1
    public static function wrapDES(#[\SensitiveParameter] string $kek, #[\SensitiveParameter] string $cek): string
    {
        $icv = substr(sha1($cek, true), 0, 8);
        $cekicv = $cek . $icv;
        $iv = Random::string(8);
        $cipher = new TripleDES('cbc');
        $cipher->disablePadding();
        $cipher->setKey($kek);
        $cipher->setIV($iv);
        $temp1 = $cipher->encrypt($cekicv);
        $temp2 = $iv . $temp1;
        $temp3 = strrev($temp2);
        $cipher->setIV("\x4a\xdd\xa2\x2c\x79\xe8\x21\x05");
        return $cipher->encrypt($temp3);
    }

    // from https://www.secg.org/sec1-v2.pdf#page=38
    // $keydatalen should be the bytelength
    public static function ANSIX963KDF(string $z, int $keydatalen, string $sharedinfo, \phpseclib4\Crypt\Hash $hash): string
    {
        $counter = "\0\0\0\1";
        $hashlen = $hash->getLengthInBytes();
        $k = '';
        for ($i = 1; $i <= ceil($keydatalen/$hashlen); $i++) {
            $k.= $hash->hash($z . $counter . $sharedinfo);
            Strings::increment_str($counter);
        }
        return substr($k, 0, $keydatalen);
    }

    public function addCertificate(X509 $cert): void
    {
        $this->cms['content']['originatorInfo']['certs'][] = ['certificate' => $cert];
    }

    public function addCRL(CRL $crl): void
    {
        $this->cms['content']['originatorInfo']['crls'][] = $crl;
    }

    public function getCertificates(): array
    {
        $certs = [];
        foreach ($this->cms['content']['originatorInfo']['certs'] as $cert) {
            switch (true) {
                // standard X509 cert
                case isset($cert['certificate']): // && $cert['certificate'] instanceof X509:
                    $certs[] = $cert['certificate'];
                //    break;
                // extended certificates are basically wrappers around regular X509 certs with unsigned attributes
                // living alongside the cert. this was intended for pre-v3 X509 certs where extensions were not
                // included
                //case isset($cert['extendedCertificate']): // obsolete
                //if ($this->isSignedBy($cert['extendedCertificate']['certificate'])) {
                //    $signingCert = $cert['extendedCertificiate']['certificate'];
                //}
                //break;
                //case isset($cert['v1AttrCert']): // obsolete
                // ['v1AttrCert']['acInfo'] = $AttributeCertificateInfoV1 ?
                //case isset($cert['v2AttrCert']):
                // ['v2AttrCert']['acInfo'] = $AttributeCertificateInfo ?
                //case isset($cert['other']):
                // ['other']['otherCert'] = ???
                //    continue 2;
            }
        }
        return $certs;
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->cms[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->cms[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->cms[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->cms[$offset]);
    }

    public function count(): int
    {
        return is_array($this->cms) ? count($this->cms) : $this->cms->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->cms->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->cms->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->cms->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->cms->next();
    }

    public function keys(): array
    {
        return $this->cms instanceof Constructed ? $this->cms->keys() : array_keys($this->cms);
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->cms->valid();
    }

    public function compile(): void
    {
        if (!$this->cms instanceof Constructed) {
            $temp = self::load($this->toString(['binary' => true]));
            $this->cms = $temp->cms;
            return;
        }
        if ($this->cms->hasEncoded()) {
            return;
        }
        $temp = self::load($this->toString(['binary' => true]))->cms['content'];
        $content = &$this->cms['content'];
        foreach ($temp as $key => $val) {
            if ($key == 'recipientInfos') {
                continue;
            }
            $content[$key] = $val;
        }
    }

    public function __debugInfo(): array
    {
         $this->compile();
        return $this->cms->__debugInfo();
    }

    public function toString(array $options = []): string
    {
        if ($this->cms instanceof Constructed) {
            ASN1::encodeDER($this->cms['content'], Maps\EnvelopedData::MAP);
            $cms = ASN1::encodeDER($this->cms, Maps\ContentInfo::MAP);
        } else {
            $temp = [
                'contentType' => $this->cms['contentType'], // 99% of the time this'll be 'id-signedData'
                'content' => new Element(ASN1::encodeDER($this->cms['content'], Maps\EnvelopedData::MAP)),
            ];
            $cms = ASN1::encodeDER($temp, Maps\ContentInfo::MAP);
            $this->cms = self::load($cms)->cms;
        }

        if ($options['binary'] ?? self::$binary) {
            return $cms;
        }

        return "-----BEGIN CMS-----\r\n" . chunk_split(Strings::base64_encode($cms), 64) . '-----END CMS-----';
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Enable binary output (DER)
     */
    public static function enableBinaryOutput(): void
    {
        self::$binary = true;
    }

    /**
     * Disable binary output (ie. enable PEM)
     */
    public static function disableBinaryOutput(): void
    {
        self::$binary = false;
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->cms instanceof Constructed ? $this->cms->toArray($convertPrimitives) : $this->cms;
    }
}