<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreAuthRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    public function register(Request $request)
    {
        try {
            $validateuser = Validator::make($request->all(),
                [
                    'name' => 'required',
                    'email' => 'required|email',
                    'password' => 'required',
                    'password_confirmation' => 'required_with:password|same:password',
                ]
            );
            if ($validateuser->fails()) {
                return response()->json(['status' => false, 'message' => 'validation error', 'errors' => $validateuser->errors()], 401);
            }
            $user = User::create(
                [
                    'name'=>$request->name,
                    'email'=>$request->email,
                    'password'=>Hash::make($request->password),
                ]
            );

            return response()->json(
                [
                    'status'=>true,
                    'message'=>'User created successful',
                    'token'=>$user->createToken('API TOKEN')->plainTextToken,
                ],201);

        } catch (\Throwable $th) {
            return response()->json(['status' => false, 'message' => $th->getMessage()],500);
        }
    }

    public function login(Request $request)
    {
        try {
            $validateuser = Validator::make($request->all(),
                [
                    'email' => 'required|email',
                    'password' => 'required',
                ]
            );
            if ($validateuser->fails()) {
                return response()->json(['status' => false, 'message' => 'validation error', 'errors' => $validateuser->errors()], 401);
            }
            if (!Auth::attempt($request->only(['email','password']))) {
                return response()->json(['status' => false, 'message' => 'Email or password is not correct!', 'errors' => $validateuser->errors()], 401);
            }
            $user=User::where('email',$request->email)->first();
            return response()->json(
                [
                    'status'=>true,
                    'message'=>'User login successful',
                    'token'=>$user->createToken('API TOKEN')->plainTextToken,
                ],200);

        }catch (\Throwable $th){
            return response()->json(['status' => false, 'message' => $th->getMessage()],500);
        }

    }

    public function logout(Request $request)
    {
        try {
            $validateuser = Validator::make($request->all(),
                [
                    'email' => 'required|email',
                    'password' => 'required',
                ]
            );
            if ($validateuser->fails()) {
                return response()->json(['status' => false, 'message' => 'validation error', 'errors' => $validateuser->errors()], 401);
            }
            if (!Auth::attempt($request->only(['email','password']))) {
                return response()->json(['status' => false, 'message' => 'Email or password is not correct!', 'errors' => $validateuser->errors()], 401);
            }
            $user=User::where('email',$request->email)->first();

            $user->tokens()->delete();
            return response()->json(
                [
                    'status'=>true,
                    'message'=>'User logout successful',
                ],200);
        }catch (\Throwable $th){
            return response()->json(['status' => false, 'message' => $th->getMessage()],500);
        }



    }

}
