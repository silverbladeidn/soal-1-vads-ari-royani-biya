<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\Clock\SystemClock;
use DateTimeImmutable;
use DateTimeZone;

class CustomerController extends Controller
{
    private $secretKey = 'Qw3rty09!@#';

    /**
     * POST /api/customer-items
     */
    public function getCustomerItems(Request $request)
    {
        try {
            // 1. Validasi bearer token
            $authHeader = $request->header('Authorization');

            if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
                return response()->json([
                    'error' => 'Token not provided or invalid format'
                ], 401);
            }

            $tokenString = substr($authHeader, 7);

            // Debug logging
            Log::info('Secret Key Used: ' . $this->secretKey);
            Log::info('Token Received: ' . $tokenString);

            // 2. Konfigurasi JWT
            $config = Configuration::forSymmetricSigner(
                new Sha256(),
                InMemory::plainText($this->secretKey)
            );

            // 3. Parse token
            try {
                $token = $config->parser()->parse($tokenString);
                Log::info('Token parsed successfully');
            } catch (\Exception $e) {
                Log::error('Token parse error: ' . $e->getMessage());
                return response()->json([
                    'error' => 'Invalid token format'
                ], 401);
            }

            // 4. Validasi token
            $constraints = [
                new SignedWith($config->signer(), $config->signingKey()),
                new ValidAt(new SystemClock(new DateTimeZone('Asia/Jakarta'))),
            ];

            if (!$config->validator()->validate($token, ...$constraints)) {
                Log::error('Token validation failed');
                return response()->json(['error' => 'Token is invalid or expired'], 401);
            }

            // 5. Validasi request body
            $request->validate([
                'name_customers' => 'required|string',
                'date_request' => 'required|date_format:Y-m-d H:i:s'
            ]);

            $nameCustomers = $request->input('name_customers');
            $dateRequest = $request->input('date_request');

            // 6. Query data dari database dengan perhitungan discount yang benar
            $results = DB::select("
                SELECT
                    u.name as name_customers,
                    m.items,
                    m.estimate_price,
                    -- Hitung discount rate berdasarkan rules
                    CASE
                        WHEN m.estimate_price < 50000 THEN 0.02
                        WHEN m.estimate_price >= 50000 AND m.estimate_price <= 1500000 THEN 0.035
                        ELSE 0.05
                    END as discount_rate,
                    -- Hitung fix price dengan discount
                    ROUND(
                        m.estimate_price - (m.estimate_price *
                            CASE
                                WHEN m.estimate_price < 50000 THEN 0.02
                                WHEN m.estimate_price >= 50000 AND m.estimate_price <= 1500000 THEN 0.035
                                ELSE 0.05
                            END
                        ),
                    0) as fix_price
                FROM user u
                INNER JOIN master_items m ON u.id = m.id_name
                WHERE u.name = ?
                ORDER BY m.id
            ", [$nameCustomers]);

            // 7. Format hasil sesuai requirement (data original dari DB)
            $formattedResults = [];

            foreach ($results as $item) {
                $formattedResults[] = [
                    'name_customers' => $item->name_customers,
                    'items' => $item->items,
                    'dicount' => number_format($item->discount_rate, 3, ',', ''),
                    'fix_price' => number_format($item->fix_price, 0, ',', '')
                ];
            }

            // 8. Log hasil query untuk debugging
            Log::info('Query results for ' . $nameCustomers . ': ', $results);

            // 9. Jika tidak ada data di database, return error atau empty array
            if (empty($formattedResults)) {
                Log::warning('No data found in database for customer: ' . $nameCustomers);
                return response()->json([
                    'result' => [],
                    'message' => 'No items found for this customer'
                ], 200);
            }

            // 10. Return response sesuai format requirement
            Log::info('Returning response for customer: ' . $nameCustomers);

            return response()->json([
                'result' => $formattedResults
            ], 200);

        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'error' => 'Validation failed',
                'messages' => $e->errors()
            ], 422);
        } catch (\Exception $e) {
            Log::error('Error in getCustomerItems: ' . $e->getMessage());
            Log::error('Stack trace: ' . $e->getTraceAsString());
            return response()->json([
                'error' => 'Internal server error: ' . $e->getMessage()
            ], 500);
        }
    }
}
