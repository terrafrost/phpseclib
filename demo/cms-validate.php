<?php
include('File/CMS.php');

$cms = new File_CMS();
$cms->load('...');
echo $cms->validateSignature() ? 'good' : 'bad';
echo "\n";
echo $cms->validateESSSignature() ? 'good' : 'bad';
echo "\n";