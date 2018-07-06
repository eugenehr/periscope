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
%% @doc Periscope API module.

-module(periscope).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").

-behaviour(gen_server).


%% API exports
-export([start/0, stop/0, start_link/0, authenticate/2, set_users/1,
         start_tunnel/2, stop_tunnel/1,
         to_binary/1, to_atom/1, md5/1, base64/1, parse_address/1]).

%% Internal functions
-export([get_transport/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).


%% Type declarations
-type login()     :: iolist().
-type password()  :: iolist() | {iolist(), plain | md5 | base64}.
-type group()     :: iolist() | atom(). 
-type user_list() :: [{login(), password()} | {login(), password(), [group()]}].

-export_type([login/0, password/0, group/0, user_list/0]).


%%====================================================================
%% API exports
%%====================================================================


-spec start() -> {ok, Started :: [atom()]} | {error, Reason :: term()}.
%%--------------------------------------------------------------------
%% @see application:ensure_all_started/1
%% @doc
%% Starts the Periscope application and all its dependencies
%% @end
%%--------------------------------------------------------------------
start() ->
    application:ensure_all_started(periscope).



-spec stop() -> ok | {error, Reason :: term()}.
%%--------------------------------------------------------------------
%% @see application:stop/0
%% @doc
%% Stops the Periscope application
%% @end
%%--------------------------------------------------------------------
stop() ->
    application:stop(periscope).



-spec(start_link() ->
    {ok, Pid :: pid()} |
    ignore |
    {error, Reason :: term()}).
%%--------------------------------------------------------------------
%% @doc
%% Starts the periscope module in a supervisor tree
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).



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
%% Authenticates a user with the given login and password
%% @end
%%--------------------------------------------------------------------
authenticate(Login, Password) ->
    periscope_users:authenticate(Login, Password).



-spec set_users(Users :: periscope:user_list()) -> ok | {error, term()}.
%%--------------------------------------------------------------------
%% @param Users the new users list
%% @doc
%% Sets users list
%% @end
%%--------------------------------------------------------------------
set_users(Users) ->
    % Stop, remove and restart the periscope_users process with new users lists
    supervisor:terminate_child(periscope_sup, periscope_users),
    supervisor:delete_child(periscope_sup, periscope_users),
    periscope_sup:add_child(worker, periscope_users, [Users]).



-spec start_tunnel(Port :: non_neg_integer() | {non_neg_integer(), non_neg_integer()} | list(), Opts :: proplists:proplist()) -> 
    {ok, Id :: atom(), Pid :: pid()} | {ok, [{Id :: atom(), Pid :: pid()}]} | {error, term()}.
%%--------------------------------------------------------------------
%% @param StartPort start of range of TCP ports to listen to
%% @param EndPort end of range of TCP ports to listen to
%% @param Opts listening options
%% @doc
%% Starts a series of TCP or SSL tunnels 
%% @end
%%--------------------------------------------------------------------
start_tunnel({StartPort, EndPort}, Opts) ->
    start_tunnel(lists:seq(StartPort, EndPort), Opts);

%%--------------------------------------------------------------------
%% @param Ports the list of TCP ports to listen to
%% @param Opts listening options
%% @doc
%% Starts a series of TCP or SSL tunnels 
%% @end
%%--------------------------------------------------------------------
start_tunnel(Ports, Opts) when is_list(Ports) ->
    {ok, lists:map(fun(Port) -> {ok, Id, Pid} = start_tunnel(Port, Opts), {Id, Pid} end, Ports)};

%%--------------------------------------------------------------------
%% @param Port TCP port to listen to
%% @param Opts listening options
%% @doc
%% Starts a TCP or SSL tunnel 
%% @end
%%--------------------------------------------------------------------
start_tunnel(Port, Opts) when is_integer(Port) ->
    NumAcceptors = proplists:get_value(num_acceptors, Opts, 3),
    MaxConnections = proplists:get_value(max_connections, Opts, infinity),
    % IP Address to bind listening socket
    {ok, IP} = parse_address(proplists:get_value(ip, Opts, proplists:get_value(ifaddr, Opts, {0, 0, 0, 0}))),
    % Transport options
    {Transport, TransOpts} = get_transport(Opts),
    % Keepalive timeout
    Keepalive = proplists:get_value(keepalive, Opts, infinity),
    % Keepalive timeout
    Encryption = proplists:get_value(encryption, Opts, none),
    % Destinations
    Dests = proplists:get_all_values(dest, Opts),
    Id = list_to_atom("periscope_tun-" ++ inet:ntoa(IP) ++ "-" ++ integer_to_list(Port)),
    %% Start listener
    {ok, Pid} = ranch:start_listener(Id, Transport, [
        {ip, IP}, 
        {port, Port},
        {num_acceptors, NumAcceptors},
        {max_connections, MaxConnections}
    ] ++ TransOpts, periscope_tun, #{keepalive => Keepalive, encryption => Encryption, dests => Dests}),
    lager:info("~ts tunnel started on ~ts:~p~n", [
        if Transport =:= ranch_ssl -> "SSL"; true -> "TCP" end,
        inet:ntoa(IP), Port]),
    {ok, Id, Pid}.



-spec stop_tunnel(Id :: atom()) ->  ok | {error, term()}.
%%--------------------------------------------------------------------
%% @param Id tunnel identifier
%% @doc
%% Stops the tunnel
%% @end
%%--------------------------------------------------------------------
stop_tunnel(Id) ->
    ranch:stop_listener(Id).



-spec to_binary(Arg :: binary() | string() | atom()) -> Bin :: binary().
%%--------------------------------------------------------------------
%% @param Arg A binary, a string or an atom to convert
%% @returns Binary
%% @doc
%% Converts a binary, a string or an atom to binary
%% @end
%%--------------------------------------------------------------------
to_binary(Arg) when is_binary(Arg) ->
    Arg;

to_binary(Arg) when is_list(Arg) ->
    list_to_binary(Arg);

to_binary(Arg) when is_atom(Arg) ->
    atom_to_binary(Arg, utf8).



-spec to_atom(Arg :: binary() | string() | atom()) -> Atom :: atom().
%%--------------------------------------------------------------------
%% @param Arg A binary, a string or an atom to convert
%% @returns Atom
%% @doc
%% Converts a binary, a string or an atom to atom
%% @end
%%--------------------------------------------------------------------
to_atom(Arg) when is_binary(Arg) ->
    binary_to_atom(Arg, utf8);

to_atom(Arg) when is_list(Arg) ->
    list_to_atom(Arg);

to_atom(Arg) when is_atom(Arg) ->
    Arg.


-spec md5(Arg :: string() | binary()) -> Hash :: binary().
%%--------------------------------------------------------------------
%% @param Arg A binary or string
%% @returns MD5 hash of the given binary
%% @doc
%% Calculates a MD5 hash of the given binary or string
%% @end
%%--------------------------------------------------------------------
md5(Arg) ->
    Bin = to_binary(Arg),
    string:uppercase(to_binary(lists:flatten([integer_to_list(X,16) || <<X>> <= erlang:md5(Bin)]))).



-spec base64(Arg :: string() | binary()) -> Hash :: binary().
%%--------------------------------------------------------------------
%% @param Arg A binary or string
%% @returns base64 hash of the given binary
%% @doc
%% Calculates a base64 hash of the given binary or string
%% @end
%%--------------------------------------------------------------------
base64(Arg) ->
    base64:encode(to_binary(Arg)).



-spec parse_address(Address :: inet:ip_address() | string() | binary() | atom()) -> 
    {ok, inet:ip_address()} | {error, Reason :: term()}.
%%--------------------------------------------------------------------
%% @param Address IP4, IP6 address or ethernet interface name
%% @doc 
%% Parses an IPv4, IPv6 address or Ethernet interface name and returns an IP address
%% @end
%%--------------------------------------------------------------------
parse_address({N1, N2, N3, N4} = IP4) when is_integer(N1), is_integer(N2), is_integer(N3), is_integer(N4) ->
    {ok, IP4};

parse_address({K1, K2, K3, K4, K5, K6, K7, K8} = IP6) when 
    is_integer(K1), is_integer(K2), is_integer(K3), is_integer(K4),
    is_integer(K5), is_integer(K6), is_integer(K7), is_integer(K8) ->
    {ok, IP6};

parse_address(Address) when is_binary(Address) ->
    parse_address(binary_to_list(Address));

parse_address(Address) when is_atom(Address) ->
    parse_address(atom_to_list(Address));

parse_address(Address) ->
    case inet:parse_address(Address) of 
        {ok, IP}        -> 
            {ok, IP};
        {error, Reason} ->
            case inet:getifaddrs() of
                {ok, Ifs} -> 
                    case proplists:get_value(Address, Ifs) of
                        undefined -> {error, no_interface};
                        IfOpts    -> case proplists:get_value(addr, IfOpts) of
                            undefined -> {error, no_address};
                            IP        -> {ok, IP} 
                        end
                    end;
                _ -> {error, Reason}
            end
    end.


%%====================================================================
%% gen_server callbacks
%%====================================================================


%% @private
init(_Opts) ->
    {ok, true}.



%% @private
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



%%====================================================================
%% Internal functions
%%====================================================================


%% @private
get_transport(Opts) ->
    % If ssl is defined in Opts then use ranch_ssl. Use ranch_tcp otherwise
    case proplists:get_value(ssl, Opts, false) of
        false   -> {ranch_tcp, proplists:get_value(tcp, Opts, [])};   
        true    -> {ranch_ssl, []};
        SslOpts -> {ranch_ssl, SslOpts}
    end.
