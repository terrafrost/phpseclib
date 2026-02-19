<?php
/**
 * Pure-PHP CMS / EncryptedData Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / CompressedData files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Random;
use phpseclib4\Exception\InsufficientSetupException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\OctetString;

/**
* Pure-PHP CMS / EncryptedData Parser
*
* @author  Jim Wigginton <terrafrost@php.net>
*/
class EncryptedData implements \ArrayAccess, \Countable, \Iterator
{
    use \phpseclib4\File\Common\Traits\KeyDerivation;

    private Constructed|array $cms;
    private string $cek; // content encryption key
    private static bool $binary = false;

    /**
     * @param string $data
     */
    public function __construct(string $data, #[\SensitiveParameter] string $key, string $encryptionAlgorithm = 'aes128-CBC-PAD')
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
            'contentType' => 'id-encryptedData',
            'content' => [
                // "If unprotectedAttrs is present, then the version MUST be 2.  If unprotectedAttrs is
                //  absent, then version MUST be 0."
                // phpseclib doesn't (currently) support unprotectedAttrs so version is hard coded as v0
                'version' => 'v0',
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
    }

    // CMS::load() takes care of the PEM / DER encoding toggling
    // if you want to load an array or Constructed as a SignedData instance you'll
    // need to call CMS\SignedData::load()
    public static function load(string|array|Constructed $encoded): self
    {
        $r = new \ReflectionClass(__CLASS__);
        $cms = $r->newInstanceWithoutConstructor();
        $cms->cms = is_string($encoded) ? self::loadString($encoded) : $encoded;
        return $cms;
    }

    private static function loadString(string $encoded): Constructed
    {
        $decoded = ASN1::decodeBER($encoded);
        $cms = ASN1::map($decoded, Maps\ContentInfo::MAP);
        $decoded = ASN1::decodeBER($cms['content']->value);
        $cms['content'] = ASN1::map($decoded, Maps\EncryptedDataCMS::MAP);
        $cms['content']->parent = $cms;
        $cms['content']->key = 'content';
        return $cms;
    }

    public function withKey(#[\SensitiveParameter] string $key): self
    {
        $this->cek = $key;
        return $this;
    }

    public function decrypt(): string
    {
        if (!isset($this->cek)) {
            throw new InsufficientSetupException('Key not set');
        }

        return $this->decryptHelper($this->cek);
    }

    public function getAlgorithm(): string
    {
        return (string) $this->cms['content']['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm'];
    }

    public function getKeyLength(): int
    {
        $cea = ASN1::decodeBER((string) $this->cms['content']['encryptedContentInfo']['contentEncryptionAlgorithm']);
        $cea = ASN1::map($cea, ASN1\Maps\AlgorithmIdentifier::MAP);
        $contentCipher = self::getPBES2EncryptionObject((string) $cea['algorithm']);
        return $contentCipher->getKeyLength();
    }

    public function getKeyLengthInBytes(): int
    {
        return $this->getKeyLength() >> 3;
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

    public function valid(): bool
    {
        $this->compile();
        return $this->cms->valid();
    }

    public function toString(array $options = []): string
    {
        if ($this->cms instanceof Constructed) {
            ASN1::encodeDER($this->cms['content'], Maps\EncryptedDataCMS::MAP);
            $cms = ASN1::encodeDER($this->cms, Maps\ContentInfo::MAP);
        } else {
            $temp = [
                'contentType' => $this->cms['contentType'], // 99% of the time this'll be 'id-encryptedData'
                'content' => new Element(ASN1::encodeDER($this->cms['content'], Maps\EncryptedDataCMS::MAP)),
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

    public function compile(): void
    {
        if (!$this->cms instanceof Constructed || !$this->cms->hasEncoded()) {
            $temp = self::load($this->toString(['binary' => true]));
            $this->cms = $temp->cms;
        }
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->cms->__debugInfo();
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->cms instanceof Constructed ? $this->cms->toArray($convertPrimitives) : $this->cms;
    }
}