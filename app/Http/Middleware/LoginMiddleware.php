<?php

namespace App\Http\Middleware;

use Closure;
use App\Models\User;
use Illuminate\Support\Facades\DB;

class LoginMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $token = $request->header('Authorization');
        if ($token) {
            $sTable = env('CUSTOM_LOGIN_TB');
            $apiToken = explode(' ', $token);
            $check = DB::connection('sqlsrv')->table($sTable)->where('token',   $apiToken[1])->first();

            if (!$check) {
                $response = array("messege" => "Token invalid.");
                return response()->json($response, 401);
            } else {
                return $next($request);
            }
        } else {
            $response = array("messege" => "Please enter the token.");
            return response()->json($response, 401);
        }
    }
}
