<?php

namespace Illuminate\Http\Middleware;

use Closure;
use Illuminate\Http\Exceptions\MalformedUrlException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ValidatePathEncoding
{
    /**
     * Validate that the incoming request path is correctly URL-encoded
     * and contains valid UTF-8 after decoding.
     *
     * @throws MalformedUrlException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $path = $request->path();

        if ($this->hasMalformedPercentEncoding($path)) {
            throw new MalformedUrlException;
        }

        if (! mb_check_encoding(rawurldecode($path), 'UTF-8')) {
            throw new MalformedUrlException;
        }

        return $next($request);
    }

    /**
     * Determine whether the path contains an invalid percent-encoded sequence.
     */
    private function hasMalformedPercentEncoding(string $path): bool
    {
        return preg_match('/%(?![0-9A-Fa-f]{2})/', $path) === 1;
    }
}
