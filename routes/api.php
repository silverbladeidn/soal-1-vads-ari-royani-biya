<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::post('/generate-token', [AuthController::class, 'generateToken']);
