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
%% @doc Periscope Tunnel tests

-module(periscope_tun_tests).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").

-include_lib("eunit/include/eunit.hrl").
-import(periscope, [to_binary/1]).


tun_test_() ->
    {timeout, 6000, [{"Periscope tunnel tests...", setup,
        fun setup/0,
        fun cleanup/1,
        {with, [
            fun(Port) -> direct_echo(Port) end,
            fun(Port) -> tunnels_range(Port) end,
            fun(Port) -> tunnels_chain(Port) end,
            fun(Port) -> encrypted_chain(Port) end
        ]}
    }]}.


setup() ->
    {ok, _} = periscope:start(),
    {ok, ServerSock} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, ServerPort} = inet:port(ServerSock),
    ServerPid = spawn_link(fun() -> echo_server({ServerSock, self()}) end),
    io:format("Echo Server ~p started on ~p port~n", [ServerPid, ServerPort]),
    gen_tcp:controlling_process(ServerSock, ServerPid),
    ServerPort.

cleanup(_) ->
    periscope:stop().


direct_echo(ServerPort) ->
    % Test direct connection
    tcp_send_recv("127.0.0.1", ServerPort).


tunnels_range(ServerPort) ->
    % Start 5 plain tcp tunnels
    {ok, IdsAndPorts} = periscope:start_tunnel({30000, 30005}, [{dest, {"127.0.0.1", ServerPort}}]),
    ok = lists:foreach(fun(Port) -> tcp_send_recv("127.0.0.1", Port) end, lists:seq(30000, 30005)),
    ok = lists:foreach(fun({Id, _Pid}) -> periscope:stop_tunnel(Id) end, IdsAndPorts).

tunnels_chain(ServerPort) ->
    {ok, Id1, _Pid1} = periscope:start_tunnel(31001, [
        {dest, {"127.0.0.1", ServerPort}}
    ]),
    {ok, Id2, _Pid2} = periscope:start_tunnel(31002, [
        {dest, {"127.0.0.1", 31001}},
        {dest, {"127.0.0.1", ServerPort}}
    ]),
    {ok, Id3, _Pid3} = periscope:start_tunnel(31003, [
        {dest, {"127.0.0.1", 31002}},
        {dest, {"127.0.0.1", 31001}},
        {dest, {"127.0.0.1", ServerPort}}
    ]),
    {ok, Id4, _Pid4} = periscope:start_tunnel(31004, [
        {dest, {"127.0.0.1", 31003}},
        {dest, {"127.0.0.1", 31002}},
        {dest, {"127.0.0.1", 31001}},
        {dest, {"127.0.0.1", ServerPort}}
    ]),

    tcp_send_recv("127.0.0.1", 31004),
    periscope:stop_tunnel(Id3),
    tcp_send_recv("127.0.0.1", 31004),
    periscope:stop_tunnel(Id2),
    tcp_send_recv("127.0.0.1", 31004),
    periscope:stop_tunnel(Id1),
    tcp_send_recv("127.0.0.1", 31004),
    
    periscope:stop_tunnel(Id4).

encrypted_chain(ServerPort) ->
    CertDir = filename:join(code:priv_dir(periscope), "test_certs"),
    {ok, Id1, _Pid1} = periscope:start_tunnel(32001, [
        {dest, {"127.0.0.1", ServerPort}}
    ]),
    {ok, Id2, _Pid2} = periscope:start_tunnel(32002, [
        {encryption, aes128gcm},
        {dest, {"127.0.0.1", 32001}}
    ]),
    {ok, Id3, _Pid3} = periscope:start_tunnel(32003, [
        {encryption, {aes192gcm, "subkey1", "password1"}},
        {dest, {"127.0.0.1", 32002, [{encryption, {aes128gcm}}]}}
    ]),
    {ok, Id4, _Pid4} = periscope:start_tunnel(32004, [
        {encryption, {aes256gcm, "subkey2", "password2", "AAD2"}},
        {dest, {"127.0.0.1", 32003, [{encryption, {aes192gcm, "subkey1", "password1"}}]}}
    ]),
    {ok, Id5, _Pid5} = periscope:start_tunnel(32005, [
        {ssl, [
            {certfile, filename:join(CertDir, "test_server.pem")}
            ,{cacertfile, filename:join(CertDir, "test_ca.pem")}
            ,{verify, verify_peer}
        ]},
        {encryption, {aes256gcm, "subkey3", "password3", "AAD3"}},
        {dest, {"127.0.0.1", 32004, [{encryption, {aes256gcm, "subkey2", "password2", "AAD2"}}]}}
    ]),
    {ok, Id6, _Pid6} = periscope:start_tunnel(32006, [
        {ssl, [
            {certfile, filename:join(CertDir, "test_server.pem")}
            ,{cacertfile, filename:join(CertDir, "test_ca.pem")}
            ,{verify, verify_peer}
        ]},
        {dest, {"localhost", 32005, [
            {encryption, {aes256gcm, "subkey3", "password3", "AAD3"}},
            {ssl, [
                {certfile, filename:join(CertDir, "test_client_ca.pem")}
                ,{cacertfile, filename:join(CertDir, "test_ca.pem")}
                ,{verify, verify_peer}
            ]}
        ]}}
    ]),

    ssl_send_recv("localhost", 32006, [
        {certfile, filename:join(CertDir, "test_client_ca.pem")}
        ,{cacertfile, filename:join(CertDir, "test_ca.pem")}
        ,{verify, verify_peer}]),
        
    [periscope:stop_tunnel(Id) || Id <- [Id1, Id2, Id3, Id4, Id5, Id6]].    
    



%%====================================================================
%% Internal functions
%%====================================================================


echo_server({Socket, Owner} = Loop) ->
    case gen_tcp:accept(Socket) of
        {ok, Sock} -> 
            gen_tcp:controlling_process(Sock, Owner),
            inet:setopts(Sock, [binary, {active, false}, {packet, raw}]),
            spawn(fun() -> echo_client(Sock) end),
            echo_server(Loop);
        Other -> Other    
    end.



echo_client(Socket) ->
    case gen_tcp:recv(Socket, 0) of
        {ok, Data} -> 
            gen_tcp:send(Socket, Data),
            echo_client(Socket);
        Other -> Other    
    end.



tcp_send_recv(Address, Port) ->
    tcp_send_recv(Address, Port, []).

tcp_send_recv(Address, Port, Opts) ->
    tcp_send_recv(Address, Port, Opts, none).

tcp_send_recv(Address, Port, Opts, EncType) ->
    {ok, Socket} = case inet:parse_address(Address) of
         {ok, IP} -> gen_tcp:connect(IP, Port, Opts);
         _        -> gen_tcp:connect(Address, Port, Opts)
    end,     
    {ok, EncS1} = periscope_crypto:client_handshake(ranch_tcp, Socket, EncType),
    inet:setopts(Socket, [binary, {active, false}]),
    
    {ok, Encrypted1, EncS2} = periscope_crypto:encrypt(gen_tcp, Socket, <<"data1">>, EncS1),
    ok = gen_tcp:send(Socket, Encrypted1),
    {ok, Encrypted2} = gen_tcp:recv(Socket, 0),
    {ok, Decrypted, _EncS3} = periscope_crypto:decrypt(gen_tcp, Socket, Encrypted2, EncS2),
    <<"data1">> = to_binary(Decrypted),
    gen_tcp:close(Socket).



ssl_send_recv(Address, Port, Opts) ->
    ssl_send_recv(Address, Port, Opts, none).

ssl_send_recv(Address, Port, Opts, EncType) ->
    {ok, Socket} = ssl:connect(Address, Port, Opts),
    {ok, EncS1} = periscope_crypto:client_handshake(ranch_ssl, Socket, EncType),
    ssl:setopts(Socket, [binary, {active, false}]),
    
    {ok, Encrypted1, EncS2} = periscope_crypto:encrypt(ssl, Socket, <<"data1">>, EncS1),
    ok = ssl:send(Socket, Encrypted1),
    {ok, Encrypted2} = ssl:recv(Socket, 0),
    {ok, Decrypted, _EncS3} = periscope_crypto:decrypt(ssl, Socket, Encrypted2, EncS2),
    <<"data1">> = to_binary(Decrypted),
    ssl:close(Socket).
