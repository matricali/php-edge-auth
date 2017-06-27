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

namespace JorgeMatricali\Security\EdgeAuth;

use JorgeMatricali\Security\EdgeAuth\ParameterException;

class Config
{
    protected $algo = 'SHA256';
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

    protected function encode($val)
    {
        if ($this->early_url_encoding === true) {
            return rawurlencode($val);
        }

        return $val;
    }

    public function set_algo($algo)
    {
        if (in_array($algo, array('sha256', 'sha1', 'md5'))) {
            $this->algo = $algo;
        } else {
            throw new Akamai_EdgeAuth_ParameterException('Invalid algorithme, must be one of "sha256", "sha1" or "md5"');
        }
    }

    public function get_algo()
    {
        return $this->algo;
    }

    public function set_ip($ip)
    {
        // @TODO: Validate IPV4 & IPV6 addrs
        $this->ip = $ip;
    }

    public function get_ip()
    {
        return $this->ip;
    }

    public function get_ip_field()
    {
        if ($this->ip != '') {
            return 'ip='.$this->ip.$this->field_delimiter;
        }

        return '';
    }

    public function set_start_time($start_time)
    {
        // verify starttime is sane
        if (strcasecmp($start_time, 'now') == 0) {
            $this->start_time = time();
        } else {
            if (is_numeric($start_time) && $start_time > 0 && $start_time < 4294967295) {
                $this->start_time = 0 + $start_time; // faster then intval
            } else {
                throw new Akamai_EdgeAuth_ParameterException('start time input invalid or out of range');
            }
        }
    }

    public function get_start_time()
    {
        return $this->start_time;
    }

    protected function get_start_time_value()
    {
        if ($this->start_time > 0) {
            return $this->start_time;
        } else {
            return time();
        }
    }

    public function get_start_time_field()
    {
        if (is_numeric($this->start_time) && $this->start_time > 0 && $this->start_time < 4294967295) {
            return 'st='.$this->get_start_time_value().$this->field_delimiter;
        } else {
            return '';
        }
    }

    public function set_window($window)
    {
        // verify window is sane
        if (is_numeric($window) && $window > 0) {
            $this->window = 0 + $window; // faster then intval
        } else {
            throw new Akamai_EdgeAuth_ParameterException('window input invalid');
        }
    }

    public function get_window()
    {
        return $this->window;
    }

    public function get_expr_field()
    {
        return 'exp='.($this->get_start_time_value() + $this->window).$this->field_delimiter;
    }

    public function set_acl($acl)
    {
        if ($this->url != '') {
            throw new Akamai_EdgeAuth_ParameterException('Cannot set both an ACL and a URL at the same time');
        }
        $this->acl = $acl;
    }

    public function get_acl()
    {
        return $this->acl;
    }

    public function get_acl_field()
    {
        if ($this->acl) {
            return 'acl='.$this->encode($this->acl).$this->field_delimiter;
        } elseif (!$this->url) {
            //return a default open acl
            return 'acl='.$this->encode('/*').$this->field_delimiter;
        }

        return '';
    }

    public function set_url($url)
    {
        if ($this->acl) {
            throw new Akamai_EdgeAuth_ParameterException('Cannot set both an ACL and a URL at the same time');
        }
        $this->url = $url;
    }

    public function get_url()
    {
        return $this->url;
    }

    public function get_url_field()
    {
        if ($this->url && !$this->acl) {
            return 'url='.$this->encode($this->url).$this->field_delimiter;
        }

        return '';
    }

    public function set_session_id($session_id)
    {
        $this->session_id = $session_id;
    }

    public function get_session_id()
    {
        return $this->session_id;
    }

    public function get_session_id_field()
    {
        if ($this->session_id) {
            return 'id='.$this->session_id.$this->field_delimiter;
        }

        return '';
    }

    public function set_data($data)
    {
        $this->data = $data;
    }

    public function get_data()
    {
        return $this->data;
    }

    public function get_data_field()
    {
        if ($this->data) {
            return 'data='.$this->data.$this->field_delimiter;
        }

        return '';
    }

    public function set_salt($salt)
    {
        $this->salt = $salt;
    }

    public function get_salt()
    {
        return $this->salt;
    }

    public function get_salt_field()
    {
        if ($this->salt) {
            return 'salt='.$this->salt.$this->field_delimiter;
        }

        return '';
    }

    public function set_key($key)
    {
        //verify the key is valid hex
        if (preg_match('/^[a-fA-F0-9]+$/', $key) && (strlen($key) % 2) == 0) {
            $this->key = $key;
        } else {
            throw new ParameterException('Key must be a hex string (a-f,0-9 and even number of chars)');
        }
    }

    public function get_key()
    {
        return $this->key;
    }

    public function set_field_delimiter($field_delimiter)
    {
        $this->field_delimiter = $field_delimiter;
    }

    public function get_field_delimiter()
    {
        return $this->field_delimiter;
    }

    public function set_early_url_encoding($early_url_encoding)
    {
        $this->early_url_encoding = $early_url_encoding;
    }

    public function get_early_url_encoding()
    {
        return $this->early_url_encoding;
    }
}
