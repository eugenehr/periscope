%% -*- coding: utf-8 -*-
%%
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
%%

%% @author Eugene Khrustalev <eugene.khrustalev@gmail.com>
%% @doc Periscope user's authentication module

-module(periscope_users).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").

-behaviour(gen_server).


%% API exports
-export([start_link/1, authenticate/2]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).


-import(periscope, [to_binary/1, base64/1, md5/1]).


%%%===================================================================
%%% API exports
%%%===================================================================


-spec(start_link(Users :: periscope:user_list()) ->
    {ok, Pid :: pid()} |
    ignore |
    {error, Reason :: term()}).
%%--------------------------------------------------------------------
%% @doc
%% Starts the authentication module in a supervisor tree.
%% @end
%%--------------------------------------------------------------------
start_link(Users) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Users, []).



-spec authenticate(Login, Password) ->
    {ok, {Login, Groups}} |
    {error, bad_password} |
    {error, not_found} when
    Login    :: iolist(),
    Password :: iolist(),
    Groups   :: [binary()].
%%--------------------------------------------------------------------
%% @param Login user's login
%% @param Password user's password
%% @doc
%% Authenticates a user with the given login and password.
%% @end
%%--------------------------------------------------------------------
authenticate(Login, Password) ->
    gen_server:call(periscope_users, {authenticate, Login, Password}).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================


-spec(init(Users :: periscope:user_list()) ->
    {ok, State :: term()} |
    {ok, State :: term(), timeout() |
    hibernate} |
    {stop, Reason :: term()} |
    ignore).
%% @private
init(Users) ->
    ets:new(periscope_users, [named_table, ordered_set, protected]),
    ets:insert(periscope_users, init_users(Users, [])),
    {ok, true}.



%% @private
handle_call({authenticate, Login, Password}, _From, State) ->
    BinLogin = to_binary(Login),
    BinPassw = to_binary(Password),
    Reply = case ets:lookup(periscope_users, BinLogin) of
        [{_User, Pass, Groups}] -> match_password(BinLogin, Pass, Groups, BinPassw);                    
        []                      -> {error, not_found}
    end,
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    {noreply, State}.



%% @private
handle_cast(_Request, State) ->
    {noreply, State}.



%% @private
handle_info(_Info, State) ->
    {noreply, State}.



%% @private
terminate(_Reason, _State) ->
    ok.



%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%%===================================================================
%%% Internal functions
%%%===================================================================


%% @private
%% @doc Converts list of users to internal form
init_users([], Acc) ->
    Acc;

init_users([{Login, Password} | Tail], Acc) ->
    init_users([{Login, Password, []} | Tail], Acc);

init_users([{Login, Password, Groups} | Tail], Acc) ->
    BinGroups = lists:sort([to_binary(Group) || Group <- Groups]),
    init_users(Tail, [{to_binary(Login), init_password(Password), BinGroups} | Acc]).



%% @private
%% @doc Converts password to internal form
init_password({Password, plain}) ->
    {to_binary(Password), plain};

init_password({Password, base64}) ->
    {to_binary(Password), base64};

init_password({Password, md5}) ->
    {string:uppercase(to_binary(Password)), md5};

init_password(Password) when is_list(Password); is_binary(Password) ->
    init_password({Password, plain}).



%% @private
%% @doc Matches user password
match_password(Login, {Password, plain}, Groups, Password) ->
    {ok, {Login, Groups}};

match_password(_Login, {_Password, plain}, _Groups, _Password2) ->
    {error, bad_password};

match_password(Login, {Base64, base64}, Groups, Password) ->
    match_password(Login, {Base64, plain}, Groups, base64(Password));

match_password(Login, {MD5, md5}, Groups, Password) ->
    match_password(Login, {MD5, plain}, Groups, md5(Password)).
