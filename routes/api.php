<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;
use App\Http\Middleware\AuthMiddleware; // Import your middleware

// Authentication routes (login, register)
Route::group([
    'prefix' => 'auth'
], function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('register', [AuthController::class, 'register']);
});

// Protected routes with 'auth:api' and your custom 'auth.refresh' middleware
Route::middleware(['auth:api', AuthMiddleware::class])->group(function () {
    Route::get('me', [AuthController::class, 'me']);           // Get current user info (GET method)
    Route::post('logout', [AuthController::class, 'logout']);   // Logout route
    Route::post('refresh', [AuthController::class, 'refresh']); // Token refresh route
});
