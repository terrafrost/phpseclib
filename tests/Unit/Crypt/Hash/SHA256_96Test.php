<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */
require_once('SHA256Test.php');

class SHA256_96Test extends SHA256Test
{
    public function getInstance()
    {
        return new Crypt_Hash('sha256-96');
    }

    /**
     * @dataProvider hashData()
     */
    public function testHash($message, $longResult)
    {
echo "SHA256_96: testHash\n";
        parent::testHash($message, substr($longResult, 0, 24));
    }

    /**
     * @dataProvider hmacData()
     */
    public function testHMAC($key, $message, $longResult)
    {
echo "SHA256_96: testHMAC\n";
        parent::testHMAC($key, $message, substr($longResult, 0, 24));
    }
}
