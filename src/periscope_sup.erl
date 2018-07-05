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
%% @doc Periscope top level supervisor

-module(periscope_sup).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").

-behaviour(supervisor).


%% API exports
-export([start_link/0, add_child/3, add_child/4, get_child/1]).
%% Supervisor callbacks
-export([init/1]).


%%====================================================================
%% API exports
%%====================================================================


-define(CHILD_SPEC(Id, Module, Opts, Type), {Id, {Module, start_link, Opts}, permanent, 5000, Type, dynamic}).
-define(SUPERV_SPEC(Id, Module, Opts), ?CHILD_SPEC(Id, Module, Opts, supervisor)).
-define(WORKER_SPEC(Id, Module, Opts), ?CHILD_SPEC(Id, Module, Opts, worker)).



-spec(start_link() ->
    {ok, Pid :: pid()} |
    ignore |
    {error, Reason :: term()}).
%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor.
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).



-spec(add_child(Type, IdModule, Opts) -> Ret when
    Type :: worker | supervisor,
    IdModule :: atom(),
    Opts :: term(),
    Ret  :: {ok, Pid :: pid()} | {error, Reason :: term()}).
%%--------------------------------------------------------------------
%% @param Type the type of the process
%% @param IdModule process identifier and module
%% @param Opts process arguments
%% @doc
%% Adds a child process to the supervisor tree.
%% @end
%%--------------------------------------------------------------------
add_child(Type, IdModule, Opts) ->
    add_child(Type, IdModule, IdModule, Opts).



-spec(add_child(Type, Id, Module, Opts) -> Ret when
    Type :: worker | supervisor,
    Id :: atom(),
    Module :: atom(),
    Opts :: term(),
    Ret  :: {ok, Pid :: pid()} | {error, Reason :: term()}).
%%--------------------------------------------------------------------
%% @param Type the type of the process
%% @param Id process identifier
%% @param Module process module
%% @param Opts process arguments
%% @doc
%% Adds a child process to the supervisor tree.
%% @end
%%--------------------------------------------------------------------
add_child(worker, Id, Module, Opts) ->
    supervisor:start_child(?MODULE, ?WORKER_SPEC(Id, Module, Opts));

add_child(supervisor, Id, Module, Opts) ->
    supervisor:start_child(?MODULE, ?SUPERV_SPEC(Id, Module, Opts)).



-spec(get_child(Id) -> Ret when
    Id :: atom(),
    Ret  :: pid() | restarting | {error, not_found}).
%%--------------------------------------------------------------------
%% @param Id process identifier
%% @doc
%% Gets the child pid by id.
%% @end
%%--------------------------------------------------------------------
get_child(Id) ->
    case [Child || {Id1, Child, _Type, _Modules} <- supervisor:which_children(?MODULE), Id1 =:= Id] of
        [] -> {error, not_found};
        [Child | _] -> {ok, Child}
    end.


%%====================================================================
%% Supervisor callbacks
%%====================================================================


%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    {ok, {{rest_for_one, 5, 10}, []}}.


%%====================================================================
%% Internal functions
%%====================================================================
