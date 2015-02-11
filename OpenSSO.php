<?php

/**
 * OpenSSO client class
 *
 * Inspired by https://github.com/jathanism/python-opensso
 *
 * Usage:
 * <code>
 * // Create an instance of the client class
 * $sso = new OpenSSO('http://dcorpataux.lsne.ch:8080/openam');
 * // Authenticate user and store the session token
 * $token = $sso->authenticate('user', 'password');
 * // Check whether a token is valid
 * $valid = $sso->is_valid_token($token);
 * // Retrieve attributes that belong to the user associated with a token
 * $attributes = $sso->attributes($token);
 * // Revoke a session
 * $sso->logout($token);
 * // Check whether the token is valid
 * $sso->is_valid_token($token);
 * </code>
 *
 * @author Damien Corpataux <damien.corpataux@citycable.ch>
 */
class OpenSSO {

    const REST_OPENSSO_LOGIN = '/identity/authenticate';
    const REST_OPENSSO_LOGOUT = '/identity/logout';
    const REST_OPENSSO_IS_TOKEN_VALID = '/identity/isTokenValid';
    const REST_OPENSSO_ATTRIBUTES = '/identity/attributes';
    //const REST_OPENSSO_COOKIE_NAME_FOR_TOKEN = '/identity/getCookieNameForToken';
    //const REST_OPENSSO_COOKIE_NAMES_TO_FORWARD = '/identity/getCookieNamesToForward';

    /**
     * The opensso server base URL (eg. http://sso.example.com:8080/openam)
     */
    public $opensso_url;

    public function __construct($opensso_url) {
        $this->opensso_url = $opensso_url;
    }

    /**
     * A shorthand for issuing HTTP requests (FIXME: it does POST request actually...)
     * @param $url The URL to call
     * @param $params An associative array of params (eg. ['param1'=>'value1'])
     * @return The HTTP response body
     * @throws RequestFailedException if the HTTP request failed (status code is not 4xx)
     */
    protected function _GET($url, $params=[]) {
        $ch = curl_init();
        curl_setopt_array($ch, array(
            CURLOPT_URL            => $url.'?'.http_build_query($params),
            CURLOPT_POST           => false,
            CURLOPT_POSTFIELDS     => false,
            CURLOPT_RETURNTRANSFER => true
        ));
        $response = curl_exec($ch);
        $response = trim($response, "\n");
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($status < 200 || $status >= 300) {
            $message = sprintf("{$response} ({$status})");
            throw new RequestFailedException($message, $status);
        }
        curl_close($ch);
        return $response;
    }

    /**
     * Returns a valid token if authentication succeeded,
     * else throws an AuthenticationFailedException
     * 
     * @param $username The username to authenticate
     * @param $password The password for the given username
     * @param $uri (TODO: this param is OK with an empty string)
     * @return A valid token if authentication succeeded
     * @throws AuthenticationFailedException if the supplied credentials are invalid
     * @throws RequestFailedException if the request to OpenSSO failed
     */
    public function authenticate($username, $password, $uri='') {
        try {
            $response = $this->_GET(
                $this->opensso_url.self::REST_OPENSSO_LOGIN,
                ['username' => $username, 'password' => $password, 'uri' => $uri]
            );
            $token = substr($response, strlen('token.id='));
            return $token;
        } catch (RequestFailedException $e) {
            if ($e->getCode() == 401) {
                throw new AuthenticationFailedException($e->getMessage());
            } else {
                throw $e;
            }
        }
    }

    /**
     * Returns true if the given token is valid, false otherwise
     * @param $token A session token
     * @return A boolean representing the token validity
     */
    public function is_valid_token($token) {
        $response = $this->_GET(
            $this->opensso_url.self::REST_OPENSSO_IS_TOKEN_VALID,
            ['tokenid' => $token]
        );
        return $response == 'boolean=true';
    }

    public function attributes($token, $attributes_names='uid') {
        // FIXME: $attributes_names seems to have no effect (ignored by OpenAM?)
        try {
            $response = $this->_GET(
                $this->opensso_url.self::REST_OPENSSO_ATTRIBUTES,
                ['subjectid' => $token, 'attributes_names' => $attributes_names]
            );
            return self::parse_attributes($response);
        } catch (RequestFailedException $e) {
            if (strpos($e->getMessage(), 'Invalid session ID') !== false) {
                throw new InvalidTokenException($e->getMessage());
            } else {
                throw $e;
            }
        }
    }
    /**
     * Returns an associative array of parsed attributes, as returned by
     * OpenAM when querying REST_OPENSSO_ATTRIBUTES
     * @static
     * @param $http_response_body The response body returned by OpenAM
     * @return An associative array of attributes
     */
    protected static function parse_attributes($http_response_body) {
        // NOTE: example string returned by OpenAM
        // userdetails.token.id=AQIC5wM2LY4SfcwxZp5vWZa08ImBbsxqcHyRacHuoCs-jBM.*AAJTSQACMDEAAlNLABM2NzQwMDk3NDkwODA5NjM2NDIz*
        // userdetails.attribute.name=sn
        // userdetails.attribute.value=amAdmin
        // userdetails.attribute.name=givenName
        // userdetails.attribute.value=amAdmin
        // userdetails.attribute.name=cn
        // userdetails.attribute.value=amAdmin
        // userdetails.attribute.name=inetUserStatus
        // userdetails.attribute.value=Active
        // userdetails.attribute.name=dn
        // userdetails.attribute.value=uid=amAdmin,ou=people,dc=openam,dc=forgerock,dc=org
        // split lines, remove non-attribute lines and
        // remove userdetail.attribute.name|value prefix
        $lines = explode("\n", $http_response_body);
        foreach ($lines as $line) {
            if (strpos($line, 'userdetails.attribute.') === 0) {
                $attribute_lines[] = explode('=', $line, 2)[1];
            }
        }
        // create an attribute associative array,
        // knowing that attributes name and value lines are alternating
        $attributes = [];
        for ($i=0; $i<count($attribute_lines); $i+=2) {
            $name = $attribute_lines[$i];
            $value = $attribute_lines[$i+1];
            // determine whether value is plain or composite
            if (preg_match_all('/(.+?=[^,]+),?/', $value, $matches)) {
                // composite value: extract data as an associative array
                $attributes[$name] = [];
                foreach ($matches[1] as $match) {
                    list($subname, $subvalue) = explode('=', $match, 2);
                    $attributes[$name][$subname] = $subvalue;
                }
            } else {
                // plain value
                $attributes[$name] = $value;
            }
        }
        return $attributes;
    }

    /**
     * Logout by revoking the given token
     * @param $token A session token
     * @throws InvalidTokenException if the given token is invalid
     * @throws RequestFailedException if the request to OpenSSO failed
     * @return null
     */
    public function logout($token) {
        try {
            $response = $this->_GET(
                $this->opensso_url.self::REST_OPENSSO_LOGOUT,
                ['subjectid' => $token]
            );
        } catch (RequestFailedException $e) {
            if (strpos($e->getMessage(), 'Invalid session ID') !== false) {
                throw new InvalidTokenException($e->getMessage());
            } else {
                throw $e;
            }
        }
    }

    public function __toString() {
        $classname = get_class($this);
        $hash = spl_object_hash($this);
        return "{$classname}@{$this->opensso_url} <{$hash}>";
    }
}

/**
 * OpenSSO client base exception
 */
class OpenSSOException extends Exception {}

/**
 * OpenSSO HTTP request failure exception
 */
class RequestFailedException extends OpenSSOException {}

/**
 * OpenSSO HTTP authentication failure exception
 */
class AuthenticationFailedException extends OpenSSOException {}

/**
 * OpenSSO HTTP invalid token exception
 */
class InvalidTokenException extends OpenSSOException {}