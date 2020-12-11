<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * This class provides each test method with a new and empty $this->scratchDir.
 */
abstract class Functional_Net_SFTPTestCase extends PhpseclibFunctionalTestCase
{
    protected $sftp;
    protected $scratchDir;

    public function setUp(): void
    {
        parent::setUp();
        $this->scratchDir = uniqid('phpseclib-sftp-scratch-');

define('NET_SSH2_LOGGING', 3);
        $this->sftp = new Net_SFTP($this->getEnv('SSH_HOSTNAME'));
        $this->assertTrue($this->sftp->login(
            $this->getEnv('SSH_USERNAME'),
            $this->getEnv('SSH_PASSWORD')
        ));
var_dump($this->sftp->getAlgorithmsNegotiated());
        $this->assertTrue($this->sftp->mkdir($this->scratchDir));
        $this->assertTrue($this->sftp->chdir($this->scratchDir));
    }

    public function tearDown(): void
    {
        if ($this->sftp) {
            $this->sftp->chdir($this->getEnv('SSH_HOME'));
            $this->sftp->delete($this->scratchDir);
        }
        parent::tearDown();
    }
}
