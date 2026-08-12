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
     * Validate the integrity and UTF-8 encoding of the incoming request path.
     *
     * The path is treated as untrusted input and is decoded exactly once.
     *
     * @throws \Illuminate\Http\Exceptions\MalformedUrlException
     */
    public function handle(Request $request, Closure $next): Response
    {
        /*
         * Symfony's getPathInfo() returns the raw path, i.e. it has not yet
         * been URL-decoded. This is important because validation must happen
         * before canonicalization/decoding as well as afterwards.
         */
        $rawPath = $request->getPathInfo();

        if (! is_string($rawPath)) {
            $this->fail();
        }

        /*
         * 1. Validate the byte stream as received.
         *
         * mb_check_encoding() validates whether the entire byte stream is
         * valid UTF-8, therefore rejecting incomplete/truncated UTF-8
         * sequences and malformed byte sequences.
         *
         * NUL is checked separately because "\0" is perfectly valid UTF-8
         * while being unsafe in path-processing contexts.
         */
        if (
            ! mb_check_encoding($rawPath, 'UTF-8')
            || str_contains($rawPath, "\0")
        ) {
            $this->fail();
        }

        /*
         * 2. Reject malformed percent-encoding BEFORE rawurldecode().
         *
         * rawurldecode() only converts "%HH" sequences; it does not report
         * malformed "%" sequences as an error. Therefore "%", "%A", "%GG",
         * etc. must explicitly be rejected.
         */
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $rawPath) === 1) {
            $this->fail();
        }

        /*
         * Decode exactly once.
         *
         * rawurldecode() has the signature:
         *
         *     rawurldecode(string $string): string
         *
         * and, unlike urldecode(), does not interpret "+" as a space.
         */
        $decodedPath = rawurldecode($rawPath);

        /*
         * 3. A percent-encoded octet surviving the first decoding pass is a
         * second encoding layer.
         *
         * Examples rejected:
         *
         *   %252e%252e%252f  -> %2e%2e%2f
         *   %2500            -> %00
         *   %252F            -> %2F
         *
         * This intentionally implements a strict canonical representation:
         * nested URL encoding is not accepted.
         */
        if (preg_match('/%[0-9A-Fa-f]{2}/', $decodedPath) === 1) {
            $this->fail();
        }

        /*
         * 4. Validate UTF-8 again AFTER decoding.
         *
         * A raw URL may contain only ASCII while percent-decoding produces
         * an invalid or truncated UTF-8 sequence:
         *
         *   %C3
         *   %E2%82
         *   %F0%9F%92
         *   %C0%AF
         *
         * Validation only before rawurldecode() would therefore be
         * insufficient.
         */
        if (! mb_check_encoding($decodedPath, 'UTF-8')) {
            $this->fail();
        }

        /*
         * 5. NUL must be rejected explicitly after decoding.
         *
         * Examples:
         *
         *   %00
         *   foo%00bar
         */
        if (str_contains($decodedPath, "\0")) {
            $this->fail();
        }

        /*
         * 6. Reject Unicode control characters.
         *
         * \p{Cc} includes C0/C1 controls such as:
         *
         *   U+0001 ... U+001F
         *   U+007F
         *   U+0080 ... U+009F
         *
         * NUL was handled explicitly above to make that security invariant
         * clear even though it also belongs to the Cc category.
         */
        $controlCharacterMatch = preg_match('/\p{Cc}/u', $decodedPath);

        if ($controlCharacterMatch !== 0) {
            /*
             * !== 0 is deliberate:
             *
             *  1     -> a control character was found
             *  false -> regex processing failed
             *
             * Either case fails closed.
             */
            $this->fail();
        }

        /*
         * 7. Reject path traversal dot-segments after canonicalization.
         *
         * Checking them before decoding would permit representations such as:
         *
         *   %2e%2e/
         *   .%2e/
         *
         * Once decoded, every segment has one canonical representation.
         */
        foreach (explode('/', str_replace('\\', '/', $decodedPath)) as $segment) {
            if ($segment === '.' || $segment === '..') {
                $this->fail();
            }
        }

        return $next($request);
    }

    /**
     * Abort processing without disclosing the offending path, bytes,
     * route structure, decoding state, or validation rule.
     *
     * No logging is performed here deliberately. If the application's
     * global exception handler logs request URIs, it should separately
     * redact them for MalformedUrlException.
     *
     * @return never
     *
     * @throws \Illuminate\Http\Exceptions\MalformedUrlException
     */
    private function fail(): never
    {
        throw new MalformedUrlException;
    }
}
