<?php

namespace NDC\Csrf;

use ArrayAccess;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TypeError;

class CsrfMiddleware implements MiddlewareInterface
{
    /**
     * @var array|ArrayAccess
     */
    private $session;
    /**
     * @var string
     */
    private $sessionKey;
    /**
     * @var string
     */
    private $formKey;
    /**
     * @var int
     */
    private $limit;

    /**
     * Constructor of CsrfMiddleware.
     *
     * @param array|ArrayAccess $session
     * @param int               $limit
     * @param string            $sessionKey
     * @param string            $formKey
     *
     * @throws \TypeError
     */
    public function __construct(
        &$session,
        int $limit = 50,
        string $sessionKey = 'csrf.tokens',
        string $formKey = '_csrf'
    ) {
        $this->testSession($session);
        $this->session = &$session;
        $this->sessionKey = $sessionKey;
        $this->formKey = $formKey;
        $this->limit = $limit;
    }

    /**
     * @param $session
     *
     * @throws \TypeError
     */
    private function testSession($session): void
    {
        if (!is_array($session) && !$session instanceof ArrayAccess) {
            throw new TypeError('Session is not an array');
        }
    }

    /**
     * Process an incoming server request and return a response, optionally delegating
     * to the next middleware component to create the response.
     *
     * @param ServerRequestInterface $request
     * @param DelegateInterface      $delegate
     *
     * @throws InvalidCsrfException
     * @throws NoCsrfException
     *
     * @return null|ResponseInterface
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate): ResponseInterface
    {
        if (in_array($request->getMethod(), ['PUT', 'POST', 'DELETE'], true)) {
            $params = $request->getParsedBody() ?: [];
            if (!array_key_exists($this->formKey, $params)) {
                throw new NoCsrfException();
            }
            if (!in_array($params[$this->formKey], $this->session[$this->sessionKey] ?? [], true)) {
                throw new InvalidCsrfException();
            }
            $this->removeToken($params[$this->formKey]);

            return $delegate->process($request);
        }

        return $delegate->process($request);
    }

    /**
     * @param string $token
     */
    private function removeToken(string $token): void
    {
        $this->session[$this->sessionKey] = array_filter(
            $this->session[$this->sessionKey] ?? [],
            function ($t) use ($token) {
                return $token !== $t;
            }
        );
    }

    /**
     * @return string
     */
    public function generateToken(): string
    {
        $token = bin2hex(random_bytes(16));
        $tokens = $this->session[$this->sessionKey] ?? [];
        $tokens[] = $token;
        $this->session[$this->sessionKey] = $this->limitTokens($tokens);

        return $token;
    }

    /**
     * @param array $tokens
     *
     * @return array
     */
    private function limitTokens(array $tokens): array
    {
        if (count($tokens) > $this->limit) {
            array_shift($tokens);
        }

        return $tokens;
    }

    /**
     * @return string
     */
    public function getSessionKey(): string
    {
        return $this->sessionKey;
    }

    /**
     * @return string
     */
    public function getFormKey(): string
    {
        return $this->formKey;
    }
}
