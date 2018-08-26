<?php

/*
MIT License
Copyright (c) 2016 Jorge Matricali
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

namespace Matricali\Security\EdgeAuth;

/**
 * [TokenAuth description].
 */
class TokenAuth
{
    public const ALGORITHM_SHA256 = 'sha256';
    public const ALGORITHM_SHA1 = 'sha1';
    public const ALGORITHM_MD5 = 'md5';

    protected $available_algorithms = [
        self::ALGORITHM_SHA256,
        self::ALGORITHM_SHA1,
        self::ALGORITHM_MD5,
    ];

    protected $algorithm = self::ALGORITHM_SHA256;
    protected $ip = '';
    protected $start_time = 0;
    protected $window = 300;
    protected $acl = '';
    protected $url = '';
    protected $session_id = '';
    protected $data = '';
    protected $salt = '';
    protected $key = 'aabbccddeeff00112233445566778899';
    protected $field_delimiter = '~';
    protected $early_url_encoding = false;

    public function __construct($key, $algorithm = self::ALGORITHM_SHA256)
    {
        $this->setKey($key);
        $this->setAlgorithm($algorithm);
    }

    public function setAlgorithm($algorithm)
    {
        if (in_array($algorithm, $this->available_algorithms)) {
            $this->algorithm = $algorithm;
        } else {
            throw new InvalidArgumentException(
                'Invalid algorithm, must be one of "sha256", "sha1" or "md5".'
            );
        }
    }

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public function setIp($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException(
                'Invalid IP, must be a valid IPv4 or IPv6 address.'
            );
        }
        $this->ip = $ip;
    }

    public function getIp()
    {
        return $this->ip;
    }

    public function getIpField()
    {
        if ('' != $this->ip) {
            return 'ip='.$this->ip.$this->field_delimiter;
        }

        return '';
    }

    public function setStartTime($start_time)
    {
        // verify starttime is sane
        if (0 == strcasecmp($start_time, 'now')) {
            $this->start_time = time();
        } else {
            if (is_numeric($start_time) && $start_time > 0 &&
                $start_time < 4294967295) {
                $this->start_time = 0 + $start_time; // faster than intval
            } else {
                throw new InvalidArgumentException(
                    'Start time input invalid or out of range.'
                );
            }
        }
    }

    public function getStartTime()
    {
        return $this->start_time;
    }

    public function getStartTimeField()
    {
        if (is_numeric($this->start_time) && $this->start_time > 0 &&
            $this->start_time < 4294967295) {
            return 'st='.$this->getStartTimeValue().$this->field_delimiter;
        }

        return '';
    }

    public function setWindow($window)
    {
        if (is_numeric($window) && $window > 0) {
            $this->window = 0 + $window; // faster than intval()
        } else {
            throw new InvalidArgumentException('Invalid window value.');
        }
    }

    public function getWindow()
    {
        return $this->window;
    }

    public function getExprField()
    {
        return 'exp='.($this->getStartTimeValue() + $this->window).
            $this->field_delimiter;
    }

    public function setAcl($acl)
    {
        if ('' != $this->url) {
            throw new InvalidArgumentException(
                'Cannot set both an ACL and a URL at the same time.'
            );
        }
        $this->acl = $acl;
    }

    public function getAcl()
    {
        return $this->acl;
    }

    public function getAclField()
    {
        if ($this->acl) {
            return 'acl='.$this->encode($this->acl).$this->field_delimiter;
        } elseif (!$this->url) {
            //return a default open acl
            return 'acl='.$this->encode('/*').$this->field_delimiter;
        }

        return '';
    }

    public function setUrl($url)
    {
        if ($this->acl) {
            throw new InvalidArgumentException(
                'Cannot set both an ACL and a URL at the same time.'
            );
        }
        $this->url = $url;
    }

    public function getUrl()
    {
        return $this->url;
    }

    public function getUrlField()
    {
        if ($this->url && !$this->acl) {
            return 'url='.$this->encode($this->url).$this->field_delimiter;
        }

        return '';
    }

    public function setSessionId($session_id)
    {
        if (!is_string($session_id) && !is_numeric($session_id)) {
            throw new InvalidArgumentException(
                'Invalid session_id value. Must be an string.'
            );
        }
        $this->session_id = $session_id;
    }

    public function getSessionId()
    {
        return $this->session_id;
    }

    public function getSessionIdField()
    {
        if ($this->session_id) {
            return 'id='.$this->session_id.$this->field_delimiter;
        }

        return '';
    }

    public function setData($data)
    {
        if (!is_string($data) && !is_numeric($data)) {
            throw new InvalidArgumentException(
                'Invalid data value. Must be an string.'
            );
        }
        $this->data = $data;
    }

    public function getData()
    {
        return $this->data;
    }

    public function getDataField()
    {
        if ($this->data) {
            return 'data='.$this->data.$this->field_delimiter;
        }

        return '';
    }

    public function setSalt($salt)
    {
        if (!is_string($salt) && !is_numeric($salt)) {
            throw new InvalidArgumentException(
                'Invalid salt value. Must be an string.'
            );
        }
        $this->salt = $salt;
    }

    public function getSalt()
    {
        return $this->salt;
    }

    public function getSaltField()
    {
        if ($this->salt) {
            return 'salt='.$this->salt.$this->field_delimiter;
        }

        return '';
    }

    public function setKey($key)
    {
        if (preg_match('/^[a-fA-F0-9]+$/', $key) && 0 == (strlen($key) % 2)) {
            $this->key = $key;
        } else {
            throw new InvalidArgumentException(
                'Key must be a hex string (a-f, 0-9 and even number of chars).'
            );
        }
    }

    public function getKey()
    {
        return $this->key;
    }

    public function setFieldDelimiter($field_delimiter)
    {
        $this->field_delimiter = $field_delimiter;
    }

    public function getFieldDelimiter()
    {
        return $this->field_delimiter;
    }

    public function setEarlyUrlEncoding($early_url_encoding)
    {
        $this->early_url_encoding = $early_url_encoding;
    }

    public function getEarlyUrlEncoding()
    {
        return $this->early_url_encoding;
    }

    public function generateToken()
    {
        $m_token = $this->getIpField();
        $m_token .= $this->getStartTimeField();
        $m_token .= $this->getExprField();
        $m_token .= $this->getAclField();
        $m_token .= $this->getSessionIdField();
        $m_token .= $this->getDataField();
        $m_token_digest = (string) $m_token;
        $m_token_digest .= $this->getUrlField();
        $m_token_digest .= $this->getSaltField();

        $signature = hash_hmac(
            $this->getAlgorithm(),
            rtrim($m_token_digest, $this->getFieldDelimiter()),
            $this->h2b($this->getKey())
        );

        return $m_token.'hmac='.$signature;
    }

    protected function encode($val)
    {
        if (true === $this->early_url_encoding) {
            return rawurlencode($val);
        }

        return $val;
    }

    protected function getStartTimeValue()
    {
        if ($this->start_time > 0) {
            return $this->start_time;
        }

        return time();
    }

    protected function h2b($str)
    {
        $bin = '';
        $i = 0;
        do {
            $bin .= chr(hexdec($str[$i].$str[($i + 1)]));
            $i += 2;
        } while ($i < strlen($str));

        return $bin;
    }
}
