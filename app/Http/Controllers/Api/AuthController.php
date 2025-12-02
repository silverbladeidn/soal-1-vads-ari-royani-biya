<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use DateTimeImmutable;

class AuthController extends Controller
{
    /**
     * POST /api/generate-token
     */
    public function generateToken(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'date_request' => 'required|date_format:Y-m-d H:i:s'
        ]);

        // Konfigurasi JWT
        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText(config('jwt.secret', env('JWT_SECRET', 'Qw3rty09!@#')))
        );

        $now = new DateTimeImmutable();
        $exp = $now->modify('+1 hour');

        // Buat Token
        $token = $config->builder()
            ->issuedAt($now)
            ->expiresAt($exp)
            ->withClaim('name', $request->name)
            ->withClaim('date_request', $request->date_request)
            ->getToken($config->signer(), $config->signingKey());

        return response()->json([
            'name' => $request->name,
            'date_request' => $request->date_request,
            'token' => $token->toString(),
            'exp' => $exp->getTimestamp()
        ]);
    }
}
