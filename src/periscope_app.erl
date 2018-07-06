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
%% @doc Periscope application

-module(periscope_app).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").


-behaviour(application).


%% Application callbacks
-export([start/2, stop/1]).


%%====================================================================
%% Application callbacks
%%====================================================================


start(_StartType, _StartArgs) ->
    lager:debug("Starting Periscope application..."),
    case init:get_argument(conf) of
        % Read configuration file passed after -conf command line argument
        {ok, [[Filename]]} ->
            case file:consult(Filename) of
                {error, Reason} -> {error, Reason};
                {ok, PropList}  -> init(PropList)
            end;
        % if no file given then load configuration from application environment
        error -> init(convert_env())
    end.



stop(_State) ->
    ok.


%%====================================================================
%% Internal functions
%%====================================================================


%% @private
%% @doc Inits the application
init(PropList) ->
    {ok, SupPid} = periscope_sup:start_link(),

    %% Start periscope
    {ok, _} = periscope_sup:add_child(worker, periscope, []),

    %% Start periscope_users
    Users = proplists:get_all_values(user, PropList),
    periscope:set_users(Users),

    %% Start tunnels
    [periscope:start_tunnel(Port, Opts) || {Port, Opts} <- proplists:get_all_values(tunnel, PropList)],
    
    {ok, SupPid}.


%% @private
%% @doc Converts application environment to file:consult/1 format
convert_env() ->
    lists:flatten(
        application:get_env(periscope, users, []),
        application:get_env(periscope, tunnels, [])
    ).
