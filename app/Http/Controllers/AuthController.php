<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Cookie; // Added for cookie handling

class AuthController extends Controller
{
    // Registration logic remains unchanged
    public function register(Request $request)
    {
        $validateData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $validateData['name'],
            'email' => $validateData['email'],
            'password' => bcrypt($validateData['password']),
        ]);

        $token = auth('api')->login($user);

        return response()->json([
            'status' => 'success',
            'message' => 'User registered successfully'
        ]);
    }

    // Login logic
    // Login logic
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if ($token = $this->guard()->attempt($credentials)) {
            $user = $this->guard()->user(); // Get the authenticated user
            $user->makeHidden('password', 'created_at', 'updated_at', 'email_verified_at');  // Hide the password field

            // Set the token in the cookie and pass user data without the password
            return $this->setTokenInCookie($token, $user);
        }

        return response()->json(['status' => 'fail', 'message' => 'Invalid Credential'], 401);
    }


    // Get authenticated user info
    public function me()
    {
        return response()->json(['status'=>'success','data'=>$this->guard()->user()]);
    }


    // Logout and remove the token
    public function logout()
    {
        $this->guard()->logout();

        // Clear the cookie
        $cookie = Cookie::forget('token');

        return response()->json(['message' => 'Successfully logged out'])->withCookie($cookie);
    }

    // Refresh token and set new cookie
    public function refresh()
    {
        $newToken = $this->guard()->refresh();
        return $this->setTokenInCookie($newToken);
    }

    // Helper function to store token in an HTTP-only cookie
    // Helper function to store token in an HTTP-only cookie
    protected function setTokenInCookie($token, $user)
    {
        // Set token in HTTP-only cookie (valid for the same time as token expiration)
        $cookie = cookie('token', $token, $this->guard()->factory()->getTTL(), '/', null, false, true, false, 'Strict');

        return response()->json([
            'status' => 'success',
            'message' => 'Login Successful',
            'user' => $user // Return user data without password
        ])->withCookie($cookie);
    }


    // Get the guard for authentication
    public function guard()
    {
        return Auth::guard('api');
    }
}
