%% -*- coding: utf-8 -*-
%% Copyright (c) Eugene Khrustalev 2018. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

%% @author Eugene Khrustalev <eugene.khrustalev@gmail.com>
%% @doc Periscope Users tests

-module(periscope_users_tests).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").

-include_lib("eunit/include/eunit.hrl").

auth_test_() ->
    {"User's authentication tests...", setup,
        fun setup/0,
        fun cleanup/1,
        [
            fun success_auth/0,
            fun fail_auth/0
        ]
    }.


setup() ->
    Users = [
       {"login1", "password1"},
       {"login2", {periscope:base64("password2"), base64}, [users, admins]},
       {"login3", {periscope:md5("password3"), md5}, ["devops", <<"sales">>]}
    ],
    {ok, SupPid} = periscope:start(),
    periscope:set_users(Users),
    SupPid.

cleanup(_SupPid) ->
    periscope:stop().


success_auth() ->
    ?assertMatch({ok, {<<"login1">>, []}}, periscope_users:authenticate("login1", "password1")),
    ?assertMatch({ok, {<<"login2">>, [<<"admins">>, <<"users">>]}}, periscope_users:authenticate("login2", "password2")),
    ?assertMatch({ok, {<<"login3">>, [<<"devops">>, <<"sales">>]}}, periscope_users:authenticate("login3", "password3")).

fail_auth() ->
    ?assertMatch({error, bad_password}, periscope_users:authenticate("login1", "password2")),
    ?assertMatch({error, not_found}, periscope_users:authenticate("login4", "password4")).
