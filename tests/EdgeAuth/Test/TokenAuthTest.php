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

namespace Matricali\Security\EdgeAuth\Test;

use Matricali\Security\EdgeAuth\TokenAuth;

class TokenAuthTest extends \PHPUnit_Framework_TestCase
{
    protected $testKey = 'a1b2c3d4e5f6';

    public function testGeneration()
    {
        $generator = new TokenAuth($this->testKey);
        $token = $generator->generateToken();
        $this->assertNotEmpty($token);
    }

    /**
     * @expectedException \Matricali\Security\EdgeAuth\InvalidArgumentException
     */
    public function testInvalidAlgorithm()
    {
        $auth = new TokenAuth($this->testKey);
        $auth->setAlgorithm('inVaLid');
    }

    public function testValidIPv4()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getIp());
        $this->assertEquals('', $auth->getIpField());

        // Valid IPv4
        $auth->setIp('127.0.0.1');
        $this->assertEquals('127.0.0.1', $auth->getIp());
        $this->assertEquals('ip=127.0.0.1'.$auth->getFieldDelimiter(), $auth->getIpField());
    }

    /**
     * @expectedException \Matricali\Security\EdgeAuth\InvalidArgumentException
     */
    public function testInvalidIPv4()
    {
        $auth = new TokenAuth($this->testKey);
        $auth->setIp('127.0.0.300');
    }

    public function testValidIPv6()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getIp());
        $this->assertEquals('', $auth->getIpField());

        // Valid IPv4
        $auth->setIp('2001:0db8:85a3:08d3:1319:8a2e:0370:7334');
        $this->assertEquals('2001:0db8:85a3:08d3:1319:8a2e:0370:7334', $auth->getIp());
        $this->assertEquals('ip=2001:0db8:85a3:08d3:1319:8a2e:0370:7334'.$auth->getFieldDelimiter(), $auth->getIpField());
    }

    /**
     * @expectedException \Matricali\Security\EdgeAuth\InvalidArgumentException
     */
    public function testInvalidIPv6()
    {
        $auth = new TokenAuth($this->testKey);
        $auth->setIp('2001:0db8:85a3:08d3:xxxx:8a2e:0370:7334');
    }

    public function testStartTime()
    {
        $auth = new TokenAuth($this->testKey);
        $gstv = new \ReflectionMethod('Matricali\Security\EdgeAuth\TokenAuth', 'getStartTimeValue');
        $gstv->setAccessible(true);

        $this->assertEquals(0, $auth->getStartTime());
        $this->assertEquals(time(), $gstv->invoke($auth));
        $this->assertEquals('', $auth->getStartTimeField());

        $auth->setStartTime('now');
        $this->assertEquals(time(), $auth->getStartTime());
        $this->assertEquals(time(), $gstv->invoke($auth));
        $this->assertEquals('st='.time().$auth->getFieldDelimiter(), $auth->getStartTimeField());

        $auth->setStartTime(12345);
        $this->assertEquals(12345, $auth->getStartTime());
        $this->assertEquals(12345, $gstv->invoke($auth));
        $this->assertEquals('st='. 12345 .$auth->getFieldDelimiter(), $auth->getStartTimeField());

        $auth = new TokenAuth($this->testKey);
        try {
            $auth->setStartTime('');
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
        $this->assertEquals(0, $auth->getStartTime());
        $this->assertEquals(time(), $gstv->invoke($auth));
        $this->assertEquals('', $auth->getStartTimeField());
    }

    public function testWindow()
    {
        $auth = new TokenAuth($this->testKey);
        // Default window time
        $this->assertEquals(300, $auth->getWindow());

        $auth->setWindow(500);
        $this->assertEquals(500, $auth->getWindow());

        $auth = new TokenAuth($this->testKey);
        try {
            $auth->setWindow('abc');
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
        $this->assertEquals(300, $auth->getWindow());

        try {
            $auth->setWindow(0);
        } catch (\Exception $e2) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e2);
        $this->assertEquals(300, $auth->getWindow());
    }

    public function testAcl()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getAcl());
        $this->assertEquals('acl=/*'.$auth->getFieldDelimiter(), $auth->getAclField());

        $auth->setAcl('test');
        $this->assertEquals('test', $auth->getAcl());
        $this->assertEquals('acl=test'.$auth->getFieldDelimiter(), $auth->getAclField());

        $auth = new TokenAuth($this->testKey);
        $auth->setUrl('https://example.com/protected/resource');
        $this->assertEquals('', $auth->getAclField()); // If we have an URL we shouldn't have an ACL

        try {
            $auth->setAcl('test');
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
    }

    public function testUrl()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getUrl());
        $this->assertEquals('', $auth->getUrlField());

        $auth->setUrl('https://example.com/protected/resource');
        $this->assertEquals('https://example.com/protected/resource', $auth->getUrl());
        $this->assertEquals('url=https://example.com/protected/resource'.$auth->getFieldDelimiter(), $auth->getUrlField());

        $auth = new TokenAuth($this->testKey);
        $auth->setAcl('test');
        $this->assertEquals('', $auth->getUrlField()); // If we have an URL we shouldn't have an ACL

        try {
            $auth->setUrl('https://example.com/');
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
    }

    public function testSession()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getSessionId());
        $this->assertEquals('', $auth->getSessionIdField());

        $auth->setSessionId('e10adc3949ba59abbe56e057f20f883e');
        $this->assertEquals('e10adc3949ba59abbe56e057f20f883e', $auth->getSessionId());
        $this->assertEquals('id=e10adc3949ba59abbe56e057f20f883e'.$auth->getFieldDelimiter(), $auth->getSessionIdField());

        $auth->setSessionId(123456778);
        $this->assertEquals('123456778', $auth->getSessionId());
        $this->assertEquals('id=123456778'.$auth->getFieldDelimiter(), $auth->getSessionIdField());

        $auth = new TokenAuth($this->testKey);
        try {
            $auth->setSessionId([]);
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
        $this->assertEquals('', $auth->getSessionId());
        $this->assertEquals('', $auth->getSessionIdField());

        try {
            $auth->setSessionId(new \StdClass());
        } catch (\Exception $e2) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e2);
        $this->assertEquals('', $auth->getSessionId());
        $this->assertEquals('', $auth->getSessionIdField());
    }

    public function testData()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getData());
        $this->assertEquals('', $auth->getDataField());

        $auth->setData('e10adc3949ba59abbe56e057f20f883e');
        $this->assertEquals('e10adc3949ba59abbe56e057f20f883e', $auth->getData());
        $this->assertEquals('data=e10adc3949ba59abbe56e057f20f883e'.$auth->getFieldDelimiter(), $auth->getDataField());

        $auth->setData(123456778);
        $this->assertEquals('123456778', $auth->getData());
        $this->assertEquals('data=123456778'.$auth->getFieldDelimiter(), $auth->getDataField());

        $auth = new TokenAuth($this->testKey);
        try {
            $auth->setData([]);
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
        $this->assertEquals('', $auth->getData());
        $this->assertEquals('', $auth->getDataField());

        try {
            $auth->setData(new \StdClass());
        } catch (\Exception $e2) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e2);
        $this->assertEquals('', $auth->getData());
        $this->assertEquals('', $auth->getDataField());
    }

    public function testSalt()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('', $auth->getSalt());
        $this->assertEquals('', $auth->getSaltField());

        $auth->setSalt('s4lt');
        $this->assertEquals('s4lt', $auth->getSalt());
        $this->assertEquals('salt=s4lt'.$auth->getFieldDelimiter(), $auth->getSaltField());

        $auth->setSalt(123456778);
        $this->assertEquals('123456778', $auth->getSalt());
        $this->assertEquals('salt=123456778'.$auth->getFieldDelimiter(), $auth->getSaltField());

        $auth = new TokenAuth($this->testKey);
        try {
            $auth->setSalt([]);
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
        $this->assertEquals('', $auth->getSalt());
        $this->assertEquals('', $auth->getSaltField());

        try {
            $auth->setSalt(new \StdClass());
        } catch (\Exception $e2) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e2);
        $this->assertEquals('', $auth->getSalt());
        $this->assertEquals('', $auth->getSaltField());
    }

    public function testKey()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals($this->testKey, $auth->getKey());

        $auth->setKey('abcd1234');
        $this->assertEquals('abcd1234', $auth->getKey());

        $auth = new TokenAuth($this->testKey);
        try {
            $auth->setKey('zxvft');
        } catch (\Exception $e1) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e1);
        $this->assertEquals($this->testKey, $auth->getKey());

        try {
            $auth->setKey('abcd1234f'); // Must be an even number of characters
        } catch (\Exception $e2) {
        }
        $this->assertInstanceOf('Matricali\Security\EdgeAuth\InvalidArgumentException', $e2);
        $this->assertEquals($this->testKey, $auth->getKey());
    }

    public function testFieldDelimiter()
    {
        $auth = new TokenAuth($this->testKey);
        $this->assertEquals('~', $auth->getFieldDelimiter());

        $auth->setFieldDelimiter('|');
        $this->assertEquals('|', $auth->getFieldDelimiter());
    }

    public function testEarlyUrlEncoding()
    {
        $encode = new \ReflectionMethod('Matricali\Security\EdgeAuth\TokenAuth', 'encode');
        $encode->setAccessible(true);

        $auth = new TokenAuth($this->testKey);
        $this->assertFalse($auth->getEarlyUrlEncoding());
        $this->assertEquals('test ', $encode->invoke($auth, 'test '));

        $auth->setEarlyUrlEncoding(true);
        $this->assertTrue($auth->getEarlyUrlEncoding());
        $this->assertEquals('test%20', $encode->invoke($auth, 'test '));
    }

    public function testSha256()
    {
        $auth = new TokenAuth($this->testKey);
        $auth->setAlgorithm(TokenAuth::ALGORITHM_SHA256);
        $token = $auth->generateToken();
        $this->assertNotEmpty($token);
    }

    public function testSha1()
    {
        $auth = new TokenAuth($this->testKey);
        $auth->setAlgorithm(TokenAuth::ALGORITHM_SHA1);
        $token = $auth->generateToken();
        $this->assertNotEmpty($token);
    }

    public function testMd5()
    {
        $auth = new TokenAuth($this->testKey);
        $auth->setAlgorithm(TokenAuth::ALGORITHM_MD5);
        $token = $auth->generateToken();
        $this->assertNotEmpty($token);
    }
}
