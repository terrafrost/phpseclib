<?php

use Rector\Config\RectorConfig;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Rules\RemovePhpseclibTestCasePolyfillMethodsRector;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/tests',
    ])
    ->withSets([
        PHPUnitSetList::PHPUNIT_80,
    ])
    ->withPhpVersion(PHP_VERSION_ID)
    ->withRules([
        RemovePhpseclibTestCasePolyfillMethodsRector::class
    ]);