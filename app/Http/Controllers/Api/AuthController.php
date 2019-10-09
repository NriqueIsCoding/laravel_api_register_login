<?php

namespace App\Http\Controllers\Api;

use App\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use validator;

class AuthController extends Controller
{
    public  $successStatus = 200;

    public function register(Request $request) {

        $validatedData = $request->validate([
            'name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed'
        ]);

        $validatedData['password'] = bcrypt($request->password);

        $user = User::create($validatedData);

        $accessToken = $user->createToken('authToken')->accessToken;

        return response(['user' => $user, 'access_token' => $accessToken]);

    }


    public function login(Request $request) {

        if (Auth::attempt(['email' => request('email'), 'password' => request('password')])){

            $user = Auth::user();
            $success['token'] = $user->createToken('myApp')->accessToken;

            return response()->json(['success' => $success], $this->successStatus); 
        } else {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // $validatedData = $request->validate([
        //     'email' => 'email|required',
        //     'password' => 'required'
        // ]);

        // if(!auth()->attempt($validatedData)) {
        //     return response(['message' => 'Invalid credentials']);
        // }
        //     $accessToken = auth()->user()->createToken('authToken')->accessToken;

        //     return response(['user' => auth()->user(), 'access_token' => $accessToken]);
    }

    public function getDetails() {

        $user = Auth::user();
        return response()->json(['success' => $user], $this->successStatus);
    }
}





