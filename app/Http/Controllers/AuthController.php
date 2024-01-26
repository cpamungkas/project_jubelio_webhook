<?php

namespace App\Http\Controllers;

use app\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $this->validate($request, [
            'userid' => 'required',
            'secretcode' => 'required'
        ]);

        $dataUserId = $request->input('userid');
        $dataSecretCode = $request->input('secretcode');

        $hashpwd = Hash::make($dataSecretCode);

        $dataTable = [
            'userid' => $dataUserId,
            'secretcode' => $hashpwd
        ];

        $sTable = env('CUSTOM_LOGIN_TB');
        $postData = DB::connection('sqlsrv')->table($sTable)->insert($dataTable);

        if ($postData) {
            $out = [
                'messege' => 'Register_success',
                'code' => '201',
            ];
        } else {
            $out = [
                'messege' => 'Register_failed',
                'code' => 404,
            ];
        }

        return response()->json($out, $out['code']);
    }

    public function login(Request $request)
    {
        $this->validate($request, [
            'userid' => 'required',
            'secretcode' => 'required'
        ]);

        $dataUserid = $request->input('userid');
        $dataSecretCode = $request->input('secretcode');

        // $user = User::where('userid', $dataUserid)->first();
        $sTable = env('CUSTOM_LOGIN_TB');
        $user = DB::connection('sqlsrv')->table($sTable)->where('userid', $dataUserid)->first();

        if (!$user) {
            $out = [
                'message' => 'login_failed',
                'code' => 401,
                'result' => [
                    'token' => null,
                ]
            ];
            return response()->json($out, $out['code']);
        }

        if (Hash::check($dataSecretCode, $user->secretcode)) {
            $newToken = $this->genRandomString();

            // $user->update([
            //     'token' => $newToken
            // ]);
            $userUpdate = DB::connection('sqlsrv')->table($sTable)->where('userid', $dataUserid)->update([
                'token' => $newToken
            ]);

            $out = [
                'message' => 'Token success',
                'code' => 200,
                'result' => [
                    'token' => $newToken,
                ]
            ];
        } else {
            $out = [
                'message' => 'Token failed',
                'code' => 401,
                'result' => [
                    'token' => null,
                ]
            ];
        }

        return response()->json($out, $out['code']);
    }

    function genRandomString($length = 150)
    {
        $character = '0123456789qwertyKANGCPabcdefghijklmnopqrstuvwxyzKompasGramediaABCDEFGHIJKLMNOPQRSTUVWXYZmE3Rd4kA2024';
        $long_character = strlen($character);
        $str = '';

        for ($i = 0; $i < $length; $i++) {
            $str .= $character[rand(0, $long_character - 2)];
        }

        return $str;
    }
}
