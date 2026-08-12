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
