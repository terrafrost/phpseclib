<?php
require_once('phpseclib/Math/BigInteger.php');

Class Secure{
    public static function decrypt($data)
    {
        $privateKey = '-----BEGIN RSA PRIVATE KEY----- 
MIIEpQIBAAKCAQEAvbngOK0shVJaWoMX1MCOcnwKM3Gd28f7ruytkRgvRrTPCeH/ 
sgc3qB5fK9XHqN5mKLd6BMmfdw+66q7HAzHDlwPv4MkvxX/QCCl4lzawH3AlSy4A 
Q8XJV0/xuwkDHohekI1pCs1ChQ2AC4uLdyeUHHOhWW4SczYPIV3WnMyn8GuduL/u 
TWb19CZpAZNSptU1dWtUuc/k0nObHH8mMdYe6FE8SBX4FJrZXnRNP+nXctYl1d2N 
UJQhxzh4ySVz/ckJUC/4i1qs+fs6W0ejnxwg9uZCf1WJ5sn1taSN9EwKfqFeIEmJ 
teImkHt9tWVAmHfpCPnoD/DTuCfhNRkOjo/OTQIDAQABAoIBAEs5pOaz+yANjBex 
PMS1aIWKGv1UwjN/cpJj81nBThVp4WFYw2pSJEY7bJ7Tz6tsKvNf9DhrvReXHBSr 
IetpUtTQ0c691nwndlOWJeNG4sREUfUiEybMCE3fO8heBWeYyG3mM8z9n69jr+5j 
8PNYtQgm7MWpuBUITS18qHhZSQkw4tZ7FESKSTGLt9Kd4ZgmwQfgNgu3CBmJtH9/ 
AMVTbS9+LN9Mpspa0G+iCv5fYTPvT/lKVJGKuB7vENvQMvzqlKH49JIsbQFUtk61 
EjV6HCmP34SSjVkcxk8/waCK1Hl3rkpw9La2fnEmIkei+AuUK57QvM0esHL/qHxG 
2AI95yECgYEA8GPcdcrHISZNxpT35+jbL5HWoECpuDlRaFNf/qm8uVDncgj4QrpZ 
nKsyzhgEVb2hPXrfswoHfr6UV28tKZC8jq7oCFdEVl7v0bSfx3xSfkWXzLeLbWJg 
sg01zU8Is3zeMXhu/NlMifdNWA35x0G8hhMm6QX9w2Djw9XekfX6YqUCgYEAygvM 
cIs6uXeGefMY8m5e0LtsIsj1RYIDZC5GgoeiXKWTngljiY+iz9A0p1FUZK5k24Cx 
DJIKiWwiDHT2nizgzOg34mFMIKjM7peq1gMzEszF5yksmdsJhR0CPt/MVFqTP2SG 
GUh9U03ggqhX69TaY2ngFVC1283aAXPYWYhRtIkCgYEAp+J2M2W9EG+53bhoMnSz 
r1NA+4ZtgZW2PxALeMV+YkYYfdG54JBYyUvfHYQ0ctUO6OsJk/arKV9cJnwkpGTK 
6zNIJZscxN1ky6ZD+IPg8QMVcwm0vF36fh8vtgU+ZGwOmaosiTYReEFYqOiJyxkj 
2tdBU3i1s1/Vcg3JdVK+3WkCgYEAv7ycoTzvWKw9+KKizQXCgtEp2ITehbzQ3RQx 
I5P1l3gl8zazuAqQFihen13F+dmpqsigu+4ng6wTT8D7fLXYC3xf9DwjU2b9O3rA 
y2Gz6SZctHbVdZhwm1shE2usa2ydCe6qd3ncPN7NrRB2hz2yld8WoQO74UCjnvdB 
nA2KhAkCgYEAplz+sA6vCjVe1MYI4sHcjVh/xoTKhH6DQ43Fv6/RYkTnZhzLpHKw 
A46m/UrrAZzNWUXSBv2vD+GXZ9jhZBVFAHGBZWng6ofl+lvT1zSD1zHuNmidIxdz 
tx47nce97bM8jyXMJOAqdoR31BXQ9aHRqvp0cRXXA1xtZBjaXyEEhbc= 
-----END RSA PRIVATE KEY-----';
        require_once("phpseclib/Crypt/RSA.php");
        $rsa = new Crypt_RSA();
        $rsa->loadKey($privateKey);
        //$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        $origin = $rsa->decrypt($data);
        return $origin;
    }
}
$data = 'WE0X9Khj+MBrgs14bKeIQ567urEnu/Gfu+S2beVAZBybp5famBwLWU86AAwAXSWm6tuPsP9Kbw+s94TqUqXnqBDCvq+jQ7n8Dx1nUeyiro6nixM3ZYMD8FGNDLjO+0BiVnOw3hqK5LDeVxeqMBefpNhf2qD5jU9L66KX3THr1TWC3+Re2xlcJ20Yv5X6isupUeVh3FVg5NyujxaMnHkijxVQTqFSwRyzVy8yqyDfpZgr+irEmw/CcDg43Lvl39UdUeidu8W1vVaHqTRW4IzlZDjj9TwXgmRT5TCYU6pe552G8SZ1IIwBXGBtJWx7dTzaJGDcy1da8Mpt7JISlt06BQ==';
$dataHex = bin2hex(base64_decode($data));
$dataB = pack("H*",$dataHex);
//var_dump(Secure::decrypt($dataB));
echo Secure::decrypt($dataB) . "\n";