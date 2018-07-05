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
%% @doc Periscope Tunnel module

-module(periscope_tun).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").

-behaviour(ranch_protocol).

%% API exports
-export([start_link/4, init/4]).

-import(periscope, [to_binary/1]).

%%%===================================================================
%%% API exports
%%%===================================================================


-spec start_link(Ref, Socket, Transport, Opts) -> {ok, pid()} | {error, term()} when
    Ref :: ranch:ref(),
    Socket :: any(),
    Transport :: module(), 
    Opts :: any().
%%--------------------------------------------------------------------
%% @param Ref the name of the listener
%% @param Socket the socket
%% @param Transport the transport handler
%% @param Opts the protocol options
%% @doc
%% Starts the tunnel process in a supervisor tree.
%% @end
%%--------------------------------------------------------------------
start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Opts]),
    {ok, Pid}.


%%%===================================================================
%%% Internal functions
%%%===================================================================


%% @private
init(Ref, Socket, Transport, #{keepalive := Keepalive, encryption := Encryption, dests := Dests}) ->
    ok = ranch:accept_ack(Ref),
    {ok, Encryption1} = periscope_crypto:server_handshake(Transport, Socket, Encryption),
    {ok, {IP1, Port1}} = Transport:peername(Socket),
    {ok, {IP2, Port2}} = Transport:sockname(Socket),
    lager:debug("Client connected from ~s~n", [inet:ntoa(IP1)]),
    % Connect to the one of the destinations
    case connect_dest(Dests, Port2) of
        {ok, Socket2, Transport2, Encryption2} ->
            {ok, {IP3, Port3}} = Transport2:peername(Socket2),
            lager:debug("Tunnel created ~s:~p <--(~s)--(~s:~p)--(~s)--> ~s:~p~n", [
                inet:ntoa(IP1), Port1, transport_name(Transport, Encryption),
                inet:ntoa(IP2), Port2, transport_name(Transport2, Encryption2),
                inet:ntoa(IP3), Port3]),
            % Tunnel data between peers
            loop(#{
                sock1 => Socket, trans1 => Transport, encrypt1 => Encryption1,
                sock2 => Socket2, trans2 => Transport2, encrypt2 => Encryption2,
                keepalive => Keepalive,
                tunnel => #{client => {IP1, Port1}, server => {IP2, Port2}, dest => {IP3, Port3}}});

        {error, not_connected} ->
            lager:error("All destinations unreachable. Closing channel~n", []),
            Transport:close(Socket);

        {error, Reason} ->
            lager:error("Could not connect to the destination. Closing channel with exit code: ~s~n", [Reason]),
            Transport:close(Socket)
    end.


%% @private
%% @doc Receives messages data from one socket and sends it to another
loop(#{sock1 := Socket1, trans1 := Transport1, sock2 := Socket2, trans2 := Transport2, tunnel := Tunnel, 
       keepalive := Keepalive, encrypt1 := Encryption1, encrypt2 := Encryption2} = State) ->
    Transport1:setopts(Socket1, [{active, once}]),
    Transport2:setopts(Socket2, [{active, once}]),
    case receive_msg(Keepalive) of
        {Type, Socket} when Type =:= tcp_closed; Type =:= ssl_closed -> 
            % If one of the sockets is closed then exit
            if
                Socket =:= Socket1 -> ok = Transport2:close(Socket2);
                Socket =:= Socket2 -> ok = Transport1:close(Socket1);
                true               -> ok
            end,
            #{client := {IP1, Port1}, server := {IP2, Port2}, dest := {IP3, Port3}} = Tunnel,
            lager:debug("Tunnel closed ~s:~p <--(~s)--(~s:~p)--(~s)--> ~s:~p~n", [
                inet:ntoa(IP1), Port1, transport_name(Transport1, Encryption1),
                inet:ntoa(IP2), Port2, transport_name(Transport2, Encryption2),
                inet:ntoa(IP3), Port3]),
            ok;

        {Type, Socket1, Data} when Type =:= ssl; Type =:= tcp ->
            % Send the received data from the client socket to the server socket
            {ok, Decrypted, Encryption11} = periscope_crypto:decrypt(Transport1, Socket1, Data, Encryption1),
            {ok, Encrypted, Encryption21} = periscope_crypto:encrypt(Transport2, Socket2, Decrypted, Encryption2),
            ok = Transport2:send(Socket2, Encrypted),
            loop(State#{encrypt1 => Encryption11, encrypt2 => Encryption21});    

        {Type, Socket2, Data} when Type =:= ssl; Type =:= tcp ->
            % Send the received data from the server socket to the client socket
            {ok, Decrypted, Encryption21} = periscope_crypto:decrypt(Transport2, Socket2, Data, Encryption2),
            {ok, Encrypted, Encryption11} = periscope_crypto:encrypt(Transport1, Socket1, Decrypted, Encryption1),
            ok = Transport1:send(Socket1, Encrypted),
            loop(State#{encrypt1 => Encryption11, encrypt2 => Encryption21});    

        {error, timeout} ->
            Transport1:close(Socket1),
            Transport2:close(Socket2),
            #{client := {IP1, Port1}, server := {IP2, Port2}, dest := {IP3, Port3}} = Tunnel,
            lager:debug("Keepalive timeout expired. Tunnel closed ~s:~p <--(~s)--(~s:~p)--(~s)--> ~s:~p~n", [
                inet:ntoa(IP1), Port1, transport_name(Transport1, Encryption1),
                inet:ntoa(IP2), Port2, transport_name(Transport2, Encryption2),
                inet:ntoa(IP3), Port3]),
            ok;    

        Other -> 
            % Flush other messages from mailbox
            lager:warning("Unexpected message received: ~p~n", [Other]),
            loop(State)
    end.



%% @private
%% @doc Receives any message from process's mailbox 
receive_msg(Timeout) when is_integer(Timeout) ->
    receive Msg   -> Msg
    after Timeout -> {error, timeout}   
    end;

receive_msg(_) ->
    receive Msg -> Msg end.


%% @private
%% @doc Connect to the one of the destinations
connect_dest([], _ServerPort) -> 
    {error, not_connected};

connect_dest([Dest | Tail], ServerPort) ->
    case connect_dest(Dest, ServerPort) of
        {ok, Socket, Transport, Encryption} -> 
            {ok, Socket, Transport, Encryption};
        {error, _Reason} -> 
            connect_dest(Tail, ServerPort)
    end;

connect_dest({Addr}, ServerPort) ->
    connect_dest({Addr, ServerPort}, ServerPort);

connect_dest({Addr, Port}, ServerPort) when is_integer(Port) ->
    connect_dest({Addr, Port, []}, ServerPort);

connect_dest({Addr, Opts}, ServerPort) when is_list(Opts) ->
    connect_dest({Addr, ServerPort, Opts}, ServerPort);

connect_dest({Addr, Port, Opts}, _ServerPort) ->
    Timeout = proplists:get_value(connect_timeout, Opts, 10000),
    % If ssl is defined in Opts then use ranch_ssl. Use ranch_tcp otherwise
    {Transport, TransOpts} = periscope:get_transport(Opts),
    % Try to connect to the destination or continue trying to the other destinations
    case catch Transport:connect(Addr, Port, TransOpts, Timeout) of
        {ok, Socket} ->
            EncType = proplists:get_value(encryption, Opts, none),
            {ok, Encryption} = periscope_crypto:client_handshake(Transport, Socket, EncType),
            lager:debug("Successfully connected to the destination ~s:~p~n", [Addr, Port]),
            {ok, Socket, Transport, Encryption};

        Reason -> 
            lager:warning("Could not connect to the destination ~s:~p: ~p~n", [Addr, Port, Reason]),
            {error, Reason} 
    end.



%% @private
%% @doc Returns transport name based on ranch transport and ecryption
transport_name(Transport, none) when Transport =:= ranch_tcp; Transport =:= gen_tcp ->
    <<"tcp">>;
transport_name(Transport, none) when Transport =:= gen_udp ->
    <<"udp">>;

transport_name(Transport, none) when Transport =:= ranch_ssl; Transport =:= ssl ->
    <<"ssl">>;

transport_name(Transport, Encryption) when is_atom(Encryption) ->
    transport_name(Transport, {Encryption});

transport_name(Transport, Encryption) when Transport =:= ranch_tcp; Transport =:= gen_tcp ->
    to_binary(element(1, Encryption));

transport_name(Transport, Encryption) when Transport =:= ranch_ssl; Transport =:= ssl ->
    Enc = to_binary(element(1, Encryption)),
    <<"ssl/", Enc/binary>>;

transport_name(Transport, _Encryption) ->
    to_binary(Transport).
    
