<?php

declare(strict_types=1);

namespace Illuminate\Http\Middleware;

use Closure;
use Illuminate\Http\Exceptions\MalformedUrlException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class ValidatePathEncoding
{
    /**
     * Validate the integrity and canonical encoding of the request path.
     *
     * @throws MalformedUrlException
     */
    public function handle(Request $request, Closure $next): Response
    {
        /*
         * Request::path() is deliberately used instead of decodedPath():
         * integrity must be checked before performing our single,
         * controlled percent-decoding pass.
         */
        $encodedPath = $request->path();

        $this->assertEncodedPathIntegrity($encodedPath);

        /*
         * rawurldecode() has a string -> string contract. With strict_types
         * enabled and a typed source, no implicit type coercion is accepted
         * at this boundary.
         */
        $decodedPath = rawurldecode($encodedPath);

        $this->assertDecodedPathIntegrity($decodedPath);

        return $next($request);
    }

    /**
     * Validate the path before percent-decoding.
     *
     * @throws MalformedUrlException
     */
    private function assertEncodedPathIntegrity(string $path): void
    {
        /*
         * Raw NUL/control bytes must never reach a decoder/router.
         *
         * \x00-\x1F = C0 control characters
         * \x7F      = DEL
         */
        if (
            str_contains($path, "\0")
            || preg_match('/[\x01-\x1F\x7F]/', $path) === 1
        ) {
            $this->reject();
        }

        /*
         * Every '%' must start exactly one valid RFC-style percent triplet.
         *
         * Reject examples:
         *   "%"
         *   "%2"
         *   "%GG"
         *   "foo%bar"  (unless '%' starts a valid %HH sequence)
         *
         * rawurldecode() itself leaves malformed '%' sequences untouched,
         * so they must be rejected before decoding.
         */
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $path) === 1) {
            $this->reject();
        }
    }

    /**
     * Validate the canonical path after exactly one decoding pass.
     *
     * @throws MalformedUrlException
     */
    private function assertDecodedPathIntegrity(string $path): void
    {
        /*
         * mb_check_encoding() validates the complete byte sequence.
         *
         * This rejects, among other malformed UTF-8 representations:
         * - truncated multibyte sequences;
         * - invalid continuation bytes;
         * - overlong/otherwise invalid UTF-8 encodings.
         *
         * NUL is valid Unicode/UTF-8, however, so it MUST be checked
         * separately.
         */
        if (! mb_check_encoding($path, 'UTF-8')) {
            $this->reject();
        }

        /*
         * U+0000 is valid UTF-8 and therefore is NOT rejected by
         * mb_check_encoding(). Treat it explicitly as an integrity failure.
         *
         * Also reject every other ASCII control character after decoding,
         * preventing payloads such as:
         *
         *   %00
         *   %0A
         *   %0D
         *   %1F
         *   %7F
         */
        if (
            str_contains($path, "\0")
            || preg_match('/[\x01-\x1F\x7F]/', $path) === 1
        ) {
            $this->reject();
        }

        /*
         * No valid %HH sequence may survive the first decoding pass.
         *
         * Examples rejected:
         *
         *   %252e%252e%252f
         *       -> %2e%2e%2f
         *
         *   %252F
         *       -> %2F
         *
         * This prevents another component from decoding the path a second
         * time and obtaining a different effective path.
         */
        if (preg_match('/%[0-9A-Fa-f]{2}/', $path) === 1) {
            $this->reject();
        }

        /*
         * Reject backslashes because different HTTP servers, frameworks
         * and filesystems may disagree about whether '\' is a path
         * separator. This removes a path-canonicalization ambiguity.
         */
        if (str_contains($path, '\\')) {
            $this->reject();
        }

        /*
         * Work only on the already canonicalized, once-decoded value.
         *
         * Reject explicit "." and ".." path segments rather than attempting
         * to normalize them. This keeps the middleware fail-closed and
         * prevents traversal semantics from being introduced downstream.
         */
        if (preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $path) === 1) {
            $this->reject();
        }
    }

    /**
     * Fail closed without reflecting attacker-controlled URL data.
     *
     * @throws MalformedUrlException
     */
    private function reject(): never
    {
        /*
         * Intentionally:
         * - no path in the exception message;
         * - no offending byte/segment;
         * - no route information;
         * - no application/filesystem details.
         */
        throw new MalformedUrlException();
    }
}
