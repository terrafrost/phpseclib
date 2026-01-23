<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Rules\RemoveClassNamePrefix;
use Rector\Rules\ShortenShaExtends;
use Rector\Rules\AddReturnTypeBaseClass;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/tests',
    ])
    ->withRules([
        //RemoveClassNamePrefix::class,
        //ShortenShaExtends::class,
        AddReturnTypeBaseClass::class
    ]);
