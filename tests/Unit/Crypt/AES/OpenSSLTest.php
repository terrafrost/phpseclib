<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class OpenSSLTest extends Unit_Crypt_AES_TestCase
{
    protected function setUp(): void
    {
        $this->engine = CRYPT_ENGINE_OPENSSL;
    }
}
