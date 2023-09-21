<?php
require __DIR__ . '/vendor/autoload.php';

$aes = new \phpseclib3\Crypt\AES('cbc');
$aes->setPreferredEngine('Eval');
$aes->setKey(str_repeat('x', 16));
$aes->setIV(str_repeat('x', 16));
echo bin2hex($aes->decrypt(str_repeat('x', 16)));