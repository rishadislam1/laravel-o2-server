<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;

class AuthMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Read the token from the cookie
        $token = $request->cookie('token');

        if ($token) {
            // Attempt to authenticate using the token
            Auth::guard('api')->setToken($token);

            if (Auth::guard('api')->check()) {
                // Token is valid, proceed to the next request
                return $next($request);
            } else {
                // Token is invalid; check if we can refresh it
                if (Auth::guard('api')->getPayload()->has('exp')) {
                    // Check if the token is about to expire
                    if (Auth::guard('api')->factory()->getPayload()->get('exp') - now()->timestamp < 300) {
                        $newToken = Auth::guard('api')->refresh();

                        // Set the new token in the cookie
                        Cookie::queue(cookie('token', $newToken, Auth::guard('api')->factory()->getTTL() * 60, '/', null, false, true, false, 'Strict'));

                        // Re-authenticate the user with the new token
                        Auth::guard('api')->setToken($newToken);
                    }
                } else {
                    // Handle missing 'exp' key
                    return response()->json(['status' => 'fail', 'message' => 'Token payload missing expiration'], 401);
                }
            }
        } else {
            // No token found in cookies; log out the user
            Auth::guard('api')->logout();
            return response()->json(['status' => 'fail', 'message' => 'Unauthorized'], 401);
        }

        // If the token is valid or refreshed, proceed
        return $next($request);
    }
}
