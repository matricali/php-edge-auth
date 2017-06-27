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

class Generator
{
    protected function h2b($str)
    {
        $bin = '';
        $i = 0;
        do {
            $bin .= chr(hexdec($str{$i}.$str{($i + 1)}));
            $i += 2;
        } while ($i < strlen($str));

        return $bin;
    }

    public function generate_token($config)
    {
        // ASSUMES:($algo='sha256', $ip='', $start_time=null, $window=300, $acl=null, $acl_url="", $session_id="", $payload="", $salt="", $key="000000000000", $field_delimiter="~")
        $m_token = $config->get_ip_field();
        $m_token .= $config->get_start_time_field();
        $m_token .= $config->get_expr_field();
        $m_token .= $config->get_acl_field();
        $m_token .= $config->get_session_id_field();
        $m_token .= $config->get_data_field();
        $m_token_digest = (string) $m_token;
        $m_token_digest .= $config->get_url_field();
        $m_token_digest .= $config->get_salt_field();

        // produce the signature and append to the tokenized string
        $signature = hash_hmac($config->get_algo(), rtrim($m_token_digest, $config->get_field_delimiter()), $this->h2b($config->get_key()));

        return $m_token.'hmac='.$signature;
    }
}
