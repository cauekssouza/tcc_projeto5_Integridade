<?php

declare(strict_types=1);

namespace Illuminate\Http\Middleware;

use Closure;
use Illuminate\Http\Exceptions\MalformedUrlException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ValidatePathEncoding
{
    /**
     * Validate the integrity and encoding of the incoming request path.
     *
     * The path is decoded exactly once and must:
     *
     * - contain only well-formed percent-encoded octets;
     * - decode to valid UTF-8;
     * - contain no NUL or control characters;
     * - contain no second URL-encoding layer.
     *
     * @throws \Illuminate\Http\Exceptions\MalformedUrlException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $path = $request->path();

        if (! is_string($path)) {
            $this->reject();
        }

        $this->validateEncodedPath($path);

        $decodedPath = rawurldecode($path);

        $this->validateDecodedPath($decodedPath);

        return $next($request);
    }

    /**
     * Validate the path before URL decoding.
     *
     * Every percent sign must belong to exactly one valid %HH sequence.
     */
    private function validateEncodedPath(string $path): void
    {
        /*
         * rawurldecode() does not reject malformed percent sequences.
         *
         * Examples rejected here:
         *
         *   %
         *   %2
         *   %GG
         *   foo%bar
         */
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $path) === 1) {
            $this->reject();
        }

        /*
         * Reject NUL/control bytes even before decoding.
         *
         * This catches raw control characters reaching the application
         * without relying on downstream HTTP-server normalization.
         */
        if ($this->containsAsciiControlCharacters($path)) {
            $this->reject();
        }
    }

    /**
     * Validate the canonical representation produced by one URL decode.
     */
    private function validateDecodedPath(string $path): void
    {
        /*
         * Explicit NUL rejection.
         *
         * Do this separately from the generic control-character check so
         * that the NUL security invariant cannot accidentally disappear if
         * that check is later changed.
         */
        if (str_contains($path, "\0")) {
            $this->reject();
        }

        /*
         * mb_check_encoding() rejects malformed and truncated UTF-8 byte
         * sequences instead of repairing/replacing them.
         *
         * Examples:
         *   incomplete multibyte sequences
         *   invalid continuation bytes
         *   overlong/otherwise invalid UTF-8 representations
         */
        if (! mb_check_encoding($path, 'UTF-8')) {
            $this->reject();
        }

        /*
         * C0 controls and DEL.
         *
         * This includes CR, LF, TAB, ESC and other bytes that can cause
         * parser/filter discrepancies.
         */
        if ($this->containsAsciiControlCharacters($path)) {
            $this->reject();
        }

        /*
         * Reject Unicode C1 control characters too.
         *
         * UTF-8 validity must be established before using a /u expression.
         */
        if (preg_match('/[\x{0080}-\x{009F}]/u', $path) === 1) {
            $this->reject();
        }

        /*
         * Decode exactly once.
         *
         * If a valid %HH sequence still exists after rawurldecode(), the
         * original path contained another URL-encoding layer.
         *
         * Examples:
         *
         *   %252e%252e  -> %2e%2e
         *   %252f       -> %2f
         *   %2500       -> %00
         *
         * A downstream component decoding the value again could otherwise
         * see different semantics from this middleware.
         */
        if (preg_match('/%[0-9A-Fa-f]{2}/', $path) === 1) {
            $this->reject();
        }
    }

    /**
     * Determine whether a string contains ASCII control bytes.
     */
    private function containsAsciiControlCharacters(string $value): bool
    {
        return preg_match('/[\x00-\x1F\x7F]/', $value) === 1;
    }

    /**
     * Fail closed without exposing any part of the rejected URL.
     *
     * Do not include the path, decoded value, route, exception details
     * or filesystem information in the exception message.
     *
     * @throws \Illuminate\Http\Exceptions\MalformedUrlException
     */
    private function reject(): never
    {
        throw new MalformedUrlException();
    }
}
