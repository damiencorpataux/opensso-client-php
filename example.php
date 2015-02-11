<?php

require_once('OpenSSO.php');

function action($text) {
    print "\n{$text}\n";
}
function value($value) {
    $dump = var_export($value, true);
    print "\033[0;37m{$dump}\033[0m"."\n";
}

action('Creating an OpenSSO client instance');
$sso = new OpenSSO('http://dcorpataux.lsne.ch:8080/openam');
value($sso);

action('Authenticating a valid user, storing token...');
$token = $sso->authenticate('amAdmin', 'password');
value($token);

action('Checking whether stored token is valid...');
value($sso->is_valid_token($token));

action('Retrieving stored token session user attributes...');
value($sso->attributes($token));

action('Revoking stored token');
value($sso->logout($token));

action('Checking whether stored token is still valid...');
value($sso->is_valid_token($token));

action('And now for something completely different: '.
       'authenticating an invalid user...');
try {
    $token = $sso->authenticate('xxx', 'yyy');
} catch (Exception $e) {
    value((string)$e);
}

action('Checking whether an invalid token is valid...');
$valid = $sso->is_valid_token('abcdefghijklmnopqsrtuvwxyz');
value($valid);

action('Revoking an invalid token...');
try {
    $token = $sso->logout('abcdefghijklmnopqsrtuvwxyz');
} catch (Exception $e) {
    value((string)$e);
}