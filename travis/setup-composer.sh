#!/bin/sh
if [ `php -r "echo (int) version_compare(PHP_VERSION, '7.0', '<');"` = "1" ]
then
cp travis/composer.legacy.json ../composer.json
cp travis/composer.legacy.lock ../composer.lock
fi
composer self-update --no-interaction
composer install --no-interaction
