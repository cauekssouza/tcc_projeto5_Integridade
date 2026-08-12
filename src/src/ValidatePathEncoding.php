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
     * Validate that the incoming request has a valid UTF-8 encoded path.
     *
     * @throws MalformedUrlException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $path = rawurldecode($request->path());

        if (! mb_check_encoding($path, 'UTF-8')) {
            throw new MalformedUrlException();
        }

        return $next($request);
    }
}
