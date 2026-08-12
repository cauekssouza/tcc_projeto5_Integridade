<?php

namespace Illuminate\Http\Middleware;

use Closure;
use Illuminate\Http\Exceptions\MalformedUrlException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ValidatePathEncoding
{
    /**
     * Validate the encoding of the incoming request path.
     *
     * @throws \Illuminate\Http\Exceptions\MalformedUrlException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $path = $request->path();

        if ($this->hasMalformedPercentEncoding($path) ||
            ! mb_check_encoding(rawurldecode($path), 'UTF-8')) {
            throw new MalformedUrlException;
        }

        return $next($request);
    }

    private function hasMalformedPercentEncoding(string $path): bool
    {
        return preg_match('/%(?![0-9A-Fa-f]{2})/', $path) === 1;
    }
}
