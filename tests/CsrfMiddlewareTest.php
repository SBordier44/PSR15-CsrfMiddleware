<?php

namespace NDC\Csrf\Tests;

use ArrayAccess;
use Interop\Http\ServerMiddleware\DelegateInterface;
use NDC\Csrf\CsrfMiddleware;
use NDC\Csrf\InvalidCsrfException;
use NDC\Csrf\NoCsrfException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;
use TypeError;

class CsrfMiddlewareTest extends TestCase
{
    public function testGetPass()
    {
        $middleware = $this->makeMiddleware();
        $delegate = $this->makeDelegate();
        $delegate->expects(static::once())->method('process');
        $middleware->process($this->makeRequest('GET'), $delegate);
    }

    private function makeMiddleware(&$session = [])
    {
        return new CsrfMiddleware($session);
    }

    private function makeDelegate()
    {
        $delegate = $this->getMockBuilder(DelegateInterface::class)->getMock();
        $delegate->method('process')->willReturn($this->makeResponse());

        return $delegate;
    }

    private function makeResponse()
    {
        return $this->getMockBuilder(ResponseInterface::class)->getMock();
    }

    private function makeRequest(string $method = 'GET', ?array $params = null)
    {
        $request = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $request->method('getMethod')->willReturn($method);
        $request->method('getParsedBody')->willReturn($params);

        return $request;
    }

    public function testPreventPost()
    {
        $middleware = $this->makeMiddleware();
        $delegate = $this->makeDelegate();
        $delegate->expects(static::never())->method('process');
        $this->expectException(NoCsrfException::class);
        $middleware->process($this->makeRequest('POST'), $delegate);
    }

    public function testPostWithValidToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $delegate = $this->makeDelegate();
        $delegate->expects(static::once())->method('process')->willReturn($this->makeResponse());
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $delegate);
    }

    public function testPostWithInvalidToken()
    {
        $middleware = $this->makeMiddleware();
        $delegate = $this->makeDelegate();
        $delegate->expects(static::never())->method('process');
        $this->expectException(InvalidCsrfException::class);
        $middleware->process($this->makeRequest('POST', ['_csrf' => 'aze']), $delegate);
    }

    public function testAcceptValidSession()
    {
        $a = [];
        $b = $this->getMockBuilder(ArrayAccess::class)->getMock();
        $middleware_a = $this->makeMiddleware($a);
        $middleware_b = $this->makeMiddleware($b);
        static::assertInstanceOf(CsrfMiddleware::class, $middleware_a);
        static::assertInstanceOf(CsrfMiddleware::class, $middleware_b);
    }

    public function testRejectInvalidSession()
    {
        $this->expectException(TypeError::class);
        $a = new stdClass();
        $middleware = $this->makeMiddleware($a);
    }

    public function testPostWithDoubleToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $delegate = $this->makeDelegate();
        $delegate->expects(static::once())->method('process')->willReturn($this->makeResponse());
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $delegate);
        $this->expectException(InvalidCsrfException::class);
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $delegate);
    }

    public function testLimitTokens()
    {
        $session = [];
        $middleware = $this->makeMiddleware($session);
        for ($i = 0; $i < 100; ++$i) {
            $token = $middleware->generateToken();
        }
        self::assertCount(50, $session[$middleware->getSessionKey()]);
        self::assertEquals($token, $session[$middleware->getSessionKey()][49]);
    }
}
