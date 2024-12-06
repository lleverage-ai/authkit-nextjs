import { NextMiddleware, NextResponse } from 'next/server';
import { updateSession } from './session.js';
import { AuthkitMiddlewareOptions } from './interfaces.js';
import { WORKOS_REDIRECT_URI } from './env-variables.js';

export function authkitMiddleware({
  debug = false,
  middlewareAuth = { enabled: false, unauthenticatedPaths: [] },
  redirectUri = WORKOS_REDIRECT_URI,
  signUpPaths = [],
}: AuthkitMiddlewareOptions = {}): NextMiddleware {
  return async function (request, event) {
    console.log({ event });

    const sessionResponse = await updateSession(request, debug, middlewareAuth, redirectUri, signUpPaths);

    // Always return a NextResponse that can be modified
    if (sessionResponse instanceof Response) {
      // Convert the Response to a NextResponse if it isn't already
      return sessionResponse instanceof NextResponse
        ? sessionResponse
        : NextResponse.next({
            status: sessionResponse.status,
            headers: sessionResponse.headers,
          });
    }

    return NextResponse.next();
  };
}
