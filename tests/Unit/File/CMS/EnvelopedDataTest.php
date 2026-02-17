<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\File\CMS;
use phpseclib4\Tests\PhpseclibTestCase;

class EnvelopedDataTest extends PhpseclibTestCase
{
    public function testPasswordDecrypt(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIHYBgkqhkiG9w0BBwOggcowgccCAQMxgYOjgYACAQCgGwYJKoZIhvcNAQUMMA4E
CBuhs+/xdgLeAgIIADAsBgsqhkiG9w0BCRADCTAdBglghkgBZQMEASoEEAYanfX/
7EvrAQFFnc0+EEgEMEeg4tDzHVLPTXAUjcSGYqLei/zHji3tvJ+hdZew3/K2XTS0
fE8HfBc01uw9GxuidTA8BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD3cN7fUkmZ
iq8UL3JxiWPigBC7AYnIQlC/X7rq8bcaeP9y
-----END
 CMS-----');
        $decrypted = $cms->getRecipients()[0]->withPassword('correct horse battery staple')->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testKeyDecrypt(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIGYBgkqhkiG9w0BBwOggYowgYcCAQIxRKJCAgEEMAYEBN6tvu8wCwYJYIZIAWUD
BAEFBCjqhj9+hBlqboSO9UybVUyjmeQ4eX8y/0x/s9JsdsWxTrrx1zNiFNzaMDwG
CSqGSIb3DQEHATAdBglghkgBZQMEASoEEA2rq3jrXhfcwE8Doq+lErqAEFqBE6fW
17lonTkG3xsJwzY=
-----END CMS-----');
        $decrypted = $cms->getRecipients()[0]->withKey(hex2bin('00112233445566778899AABBCCDDEEFF'))->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testNewPassword(): void
    {
        $plaintext = 'zzz';
        $password = 'password';
        $cms = new CMS\EnvelopedData($plaintext);
        //CMS\EnvelopedData::setPRF('id-hmacWithSHA1');
        $recipient = $cms->createNewRecipientFromPassword($password);
        $recipient->withPassword($password)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
        $cms = CMS::load("$cms");
        $decrypted = $cms->getRecipients()[0]->withPassword($password)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
    }
}
