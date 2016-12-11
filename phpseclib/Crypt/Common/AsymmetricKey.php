<?php

/**
 * Base Class for all asymmetric key ciphers
 *
 * PHP version 5
 *
 * @category  Crypt
 * @package   AsymmetricKey
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\Common;

/**
 * Base Class for all stream cipher classes
 *
 * @package AsymmetricKey
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class AsymmetricKey
{
    /**
     * Precomputed Zero
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    protected static $zero;

    /**
     * Precomputed One
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    protected static $one;

    /**
     * Engine
     *
     * This is only used for key generation. Valid values are RSA::ENGINE_INTERNAL and RSA::ENGINE_OPENSSL
     *
     * @var int
     * @access private
     */
    protected static $engine = NULL;

    /**
     * OpenSSL configuration file name.
     *
     * Set to null to use system configuration file.
     *
     * @see self::createKey()
     * @var mixed
     * @access public
     */
    protected static $configFile;

    /**
     * Supported file formats (lower case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $fileFormats = [];

    /**
     * Supported file formats (original case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $origFileFormats = [];

    /**
     * Password
     *
     * @var string
     * @access private
     */
    protected $password = false;

    /**
     * Loaded File Format
     *
     * @var string
     * @access private
     */
    protected $format = false;

    /**
     * Private Key Format
     *
     * @var string
     * @access private
     */
    protected $privateKeyFormat = 'PKCS8';

    /**
     * Public Key Format
     *
     * @var string
     * @access private
     */
    protected $publicKeyFormat = 'PKCS8';

    /**#@+
     * @access private
     * @see self::__construct()
     */
    /**
     * To use the pure-PHP implementation
     */
    const ENGINE_INTERNAL = 1;
    /**
     * To use the OpenSSL library
     *
     * (if enabled; otherwise, the internal implementation will be used)
     */
    const ENGINE_OPENSSL = 2;
    /**#@-*/

    /**
     * Tests engine validity
     *
     * @access public
     * @param int $val
     */
    public static function isValidEngine($val)
    {
        switch ($val) {
            case self::ENGINE_OPENSSL:
                return extension_loaded('openssl') && file_exists(self::$configFile);
            case self::ENGINE_INTERNAL:
                return true;
        }

        return false;
    }

    /**
     * Sets the engine
     *
     * Only used in RSA::createKey. Valid values are RSA::ENGINE_OPENSSL and RSA::ENGINE_INTERNAL
     *
     * @access public
     * @param int $val
     */
    public static function setPreferredEngine($val)
    {
        static::$engine = null;
        $candidateEngines = [
            $val,
            self::ENGINE_OPENSSL
        ];
        foreach ($candidateEngines as $engine) {
            if (static::isValidEngine($engine)) {
                static::$engine = $engine;
                break;
            }
        }
        if (!isset(static::$engine)) {
            static::$engine = self::ENGINE_INTERNAL;
        }
    }

    /**
     * Returns the engine
     *
     * @access public
     * @return int
     */
    public static function getEngine()
    {
        return self::$engine;
    }

    /**
     * Initialize static variables
     *
     * @access private
     */
    protected static function initialize_static_variables()
    {
        if (!isset(self::$zero)) {
            self::$zero= new BigInteger(0);
            self::$one = new BigInteger(1);
            self::$configFile = __DIR__ . '/../openssl.cnf';
        }

        if (!isset(self::$fileFormats)) {
            self::$fileFormats[static::ALGORITHM] = [];
            foreach (glob(__DIR__ . '/' . static::ALGORITHM . '/*.php') as $file) {
                $name = pathinfo($file, PATHINFO_FILENAME);
                $type = 'phpseclib\Crypt\\' . static::ALGORITHM . '\\' . $name;
                self::$fileFormats[static::ALGORITHM][strtolower($name)] = $type;
                self::$origFileFormats[static::ALGORITHM][] = $name;
            }
        }
    }

    /**
     * Load the key
     *
     * @access private
     * @param string $key
     * @param string $type
     * @return array
     */
    protected function load($key, $type)
    {
        $components = false;
        if ($type === false) {
            foreach (static::$fileFormats[static::ALGORITHM] as $format) {
                try {
                    $components = $format::load($key, $this->password);
                } catch (\Exception $e) {
                    $components = false;
                }
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $format = strtolower($type);
            if (isset(static::$fileFormats[static::ALGORITHM][$format])) {
                $format = static::$fileFormats[static::ALGORITHM][$format];
                $components = $format::load($key, $this->password);
            }
        }

        if ($components === false) {
            $this->format = false;
            return false;
        }

        $this->format = $format;

        return $components;
    }

    /**
     * Load the public key
     *
     * @access private
     * @param string $key
     * @param string $type
     * @return array
     */
    protected function setPublicKey($key, $type)
    {
        $components = false;
        if ($type === false) {
            foreach (static::$fileFormats[static::ALGORITHM] as $format) {
                if (!method_exists($format, 'savePublicKey')) {
                    continue;
                }
                try {
                    $components = $format::load($key, $this->password);
                } catch (\Exception $e) {
                    $components = false;
                }
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $format = strtolower($type);
            if (isset(static::$fileFormats[static::ALGORITHM][$format])) {
                $format = static::$fileFormats[static::ALGORITHM][$format];
                $components = $format::load($key, $this->password);
            }
        }

        if ($components === false) {
            $this->format = false;
            return false;
        }

        $this->format = $format;

        return $components;
    }

    /**
     * Returns a list of supported formats.
     *
     * @access public
     * @return array
     */
    public static function getSupportedFormats()
    {
        self::initialize_static_variables();

        return self::$origFileFormats[static::ALGORITHM];
    }

    /**
     * Add a fileformat plugin
     *
     * The plugin needs to either already be loaded or be auto-loadable.
     * Loading a plugin whose shortname overwrite an existing shortname will overwrite the old plugin.
     *
     * @see self::load()
     * @param string $fullname
     * @access public
     * @return bool
     */
    public static function addFileFormat($fullname)
    {
        self::initialize_static_variables();

        if (class_exists($fullname)) {
            $meta = new \ReflectionClass($path);
            $shortname = $meta->getShortName();
            self::$fileFormats[static::ALGORITHM][strtolower($shortname)] = $fullname;
            self::$origFileFormats[static::ALGORITHM][] = $shortname;
        }
    }

    /**
     * __toString() magic method
     *
     * @access public
     * @return string
     */
    public function __toString()
    {
        try {
            $key = $this->getPrivateKey($this->privateKeyFormat);
            if (is_string($key)) {
                return $key;
            }
            $key = $this->getPrivatePublicKey($this->publicKeyFormat);
            return is_string($key) ? $key : '';
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * __clone() magic method
     *
     * @access public
     * @return static
     */
    public function __clone()
    {
        $key = new static();
        $key->load($this);
        return $key;
    }

    /**
     * Determines the private key format
     *
     * @see self::__toString()
     * @access public
     * @param string $format
     */
    public function setPrivateKeyFormat($format)
    {
        $this->privateKeyFormat = $format;
    }

    /**
     * Determines the public key format
     *
     * @see self::__toString()
     * @access public
     * @param string $format
     */
    public function setPublicKeyFormat($format)
    {
        $this->publicKeyFormat = $format;
    }

    /**
     * Returns the format of the loaded key.
     *
     * If the key that was loaded wasn't in a valid or if the key was auto-generated
     * with RSA::createKey() then this will return false.
     *
     * @see self::load()
     * @access public
     * @return mixed
     */
    public function getLoadedFormat()
    {
        if ($this->format === false) {
            return false;
        }

        $meta = new \ReflectionClass($this->format);
        return $meta->getShortName();
    }
}
