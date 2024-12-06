import { NextMiddleware, NextResponse } from 'next/server';
import type { NextFetchEvent, NextRequest } from 'next/server';
import { updateSession } from './session.js';
import { AuthkitMiddlewareOptions } from './interfaces.js';
import { WORKOS_REDIRECT_URI } from './env-variables.js';

export function authkitMiddleware({
  debug = false,
  middlewareAuth = { enabled: false, unauthenticatedPaths: [] },
  redirectUri = WORKOS_REDIRECT_URI,
  signUpPaths = [],
}: AuthkitMiddlewareOptions = {}): NextMiddleware {
  return async function middleware(request: NextRequest, event: NextFetchEvent): Promise<NextResponse> {
    console.log('AuthKit Middleware Event:', event);

    if (debug) {
      console.log('AuthKit Middleware Request:', {
        url: request.url,
        path: request.nextUrl.pathname,
        auth: middlewareAuth,
      });
    }

    const sessionResponse = await updateSession(request, debug, middlewareAuth, redirectUri, signUpPaths);

    // Since updateSession now always returns NextResponse, we can just return it directly
    return sessionResponse;
  };
}
