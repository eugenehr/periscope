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
%% @doc Periscope Crypto module


-module(periscope_crypto).
-author("Eugene Khrustalev <eugene.khrustalev@gmail.com>").


%% API exports
-export([server_handshake/3, client_handshake/3, encrypt/4, decrypt/4]).

-import(periscope, [to_binary/1]).


%%%===================================================================
%%% API exports
%%%===================================================================

% 2048-bit prime number from RFC 3526 and its generator
% https://www.ietf.org/rfc/rfc3526.txt
-define(DH_PRIME, 16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF).
-define(DH_GENERATOR, 2).


% Default info used to bind generated subkey to a specific application context
-define(DEFAULT_INFOKEY, "ss-subkey"). 
% Default associated authentication data
-define(DEFAULT_AAD, <<>>).


-ifdef(DEBUG).
-define(HANDSHAKE_TIMEOUT, infinity).
-define(READ_TIMEOUT, infinity).
-else.
-define(HANDSHAKE_TIMEOUT, 500).
-define(READ_TIMEOUT, 500).
-endif.


-spec server_handshake(Transport, Socket, EncType) -> {ok, EncState} | {error, Reason} when
    Transport :: module(),
    Socket    :: inet:socket(),
    EncType   :: none | tuple(),
    EncState  :: any(),
    Reason    :: term().
%%--------------------------------------------------------------------
%% @param Socket the socket
%% @param Transport ranch transport
%% @param EncType the type of the encryption
%% @doc
%% Starts a handshake procedure on the server.
%% @end
%%--------------------------------------------------------------------
server_handshake(Transport, Socket, none) -> 
    Transport:setopts(Socket, [{packet, 0}]),
    {ok, none};

server_handshake(Transport, Socket, EncType) when is_atom(EncType) -> 
    server_handshake(Transport, Socket, {EncType});

server_handshake(Transport, Socket, {EncType}) ->
    server_handshake(Transport, Socket, {EncType, ?DEFAULT_INFOKEY});

server_handshake(Transport, Socket, {EncType, InfoKey}) when EncType =:= aes128gcm; 
        EncType =:= aes192gcm; EncType =:= aes256gcm; EncType =:= chacha20_poly1305 -> 
    % Receive P, G and client Public Key, generate and exchange Session secret key with Diffie-Hellman algo
    Transport:setopts(Socket, [{packet, 2}, binary, {active, false}]),
    {ok, ClientHello} = Transport:recv(Socket, 0, ?HANDSHAKE_TIMEOUT), 
    {KeySize, _NonceSize, _TagSize} = crypto_sizes(EncType),
    <<"C1", 
        DHPrimeSize:16/integer-big, DHPrimeBin:DHPrimeSize/binary, 
        DHGenSize:16/integer-big, DHGenBin:DHGenSize/binary, 
        Salt:KeySize/binary, ClientPub/binary>> = ClientHello,
    DHPrime = binary:decode_unsigned(DHPrimeBin, big), DHGen = binary:decode_unsigned(DHGenBin, big),
    DHParams = [DHPrime, DHGen],
    {ServerPub, ServerPriv} = crypto:generate_key(dh, DHParams),
    ServerHello = <<"S1", ServerPub/binary>>,
    ok = Transport:send(Socket, ServerHello),
    Password = crypto:compute_key(dh, ClientPub, ServerPriv, DHParams),
    server_handshake(Transport, Socket, {EncType, InfoKey, Password, ?DEFAULT_AAD, Salt});

server_handshake(Transport, Socket, {EncType, InfoKey, Password}) when EncType =:= aes128gcm; 
        EncType =:= aes192gcm; EncType =:= aes256gcm; EncType =:= chacha20_poly1305 -> 
    Transport:setopts(Socket, [{packet, 0}, {active, false}]),
    {KeySize, _NonceSize, _TagSize} = crypto_sizes(EncType),
    {ok, Salt} = Transport:recv(Socket, KeySize, ?HANDSHAKE_TIMEOUT), 
    server_handshake(Transport, Socket, {EncType, InfoKey, Password, ?DEFAULT_AAD, Salt});

server_handshake(Transport, Socket, {EncType, InfoKey, Password, AAD, DeSalt}) when EncType =:= aes128gcm; 
        EncType =:= aes192gcm; EncType =:= aes256gcm; EncType =:= chacha20_poly1305 -> 
    Transport:setopts(Socket, [{packet, 0}]),
    % Generate key and salt for backward encryption and send salt to the client 
    {EnKey, EnSalt} = subkey(EncType, to_binary(Password), to_binary(InfoKey)),
    ok = Transport:send(Socket, EnSalt),
    {DeKey, DeSalt} = subkey(EncType, to_binary(Password), to_binary(InfoKey), DeSalt),
    {ok, {EncType, {0, EnKey, to_binary(AAD)}, {0, DeKey, to_binary(AAD)}}}.



-spec client_handshake(Transport, Socket, EncType) -> {ok, EncState} | {error, Reason} when
    Transport :: module(),
    Socket    :: inet:socket(),
    EncType   :: none | aes128gcm | aes192gcm | aes256gcm | chacha20_poly1305,
    EncState  :: any(),
    Reason    :: term().
%%--------------------------------------------------------------------
%% @param Socket the socket
%% @param Transport ranch transport
%% @param EncType the type of the encryption
%% @doc
%% Starts a handshake procedure on the client.
%% @end
%%--------------------------------------------------------------------
client_handshake(_Transport, _Socket, none) -> 
    {ok, none};

client_handshake(Transport, Socket, EncType) when is_atom(EncType) -> 
    client_handshake(Transport, Socket, {EncType});

client_handshake(Transport, Socket, {EncType}) when is_atom(EncType) -> 
    client_handshake(Transport, Socket, {EncType, ?DEFAULT_INFOKEY});

client_handshake(Transport, Socket, {EncType, InfoKey}) when EncType =:= aes128gcm; 
        EncType =:= aes192gcm; EncType =:= aes256gcm; EncType =:= chacha20_poly1305 -> 
    % Generate P,G and Session secret key according to Diffie-Helman algorithm and exchange with server 
    Transport:setopts(Socket, [{packet, 2}, {active, false}]),
    DHPrime = ?DH_PRIME, DHGen = ?DH_GENERATOR,
    DHParams = [DHPrime, DHGen],
    {ClientPub, ClientPriv} = crypto:generate_key(dh, DHParams),
    DHPrimeBin = binary:encode_unsigned(DHPrime, big), DHGenBin = binary:encode_unsigned(DHGen, big),
    DHPrimeSize = byte_size(DHPrimeBin), DHGenSize = byte_size(DHGenBin),
    Salt = create_salt(EncType),
    ClientHello = <<"C1", 
        DHPrimeSize:16/integer-big, DHPrimeBin/binary, 
        DHGenSize:16/integer-big, DHGenBin/binary, 
        Salt/binary, ClientPub/binary>>,
    ok = Transport:send(Socket, ClientHello),
    {ok, ServerHello} = Transport:recv(Socket, 0, ?HANDSHAKE_TIMEOUT),
    <<"S1", ServerPub/binary>> = ServerHello,
    Password = crypto:compute_key(dh, ServerPub, ClientPriv, DHParams),
    client_handshake(Transport, Socket, {EncType, InfoKey, Password, ?DEFAULT_AAD, Salt});

client_handshake(Transport, Socket, {EncType, InfoKey, Password}) when EncType =:= aes128gcm; 
        EncType =:= aes192gcm; EncType =:= aes256gcm; EncType =:= chacha20_poly1305 -> 
    Salt = create_salt(EncType),
    ok = Transport:send(Socket, Salt),
    client_handshake(Transport, Socket, {EncType, InfoKey, Password, ?DEFAULT_AAD, Salt});

client_handshake(Transport, Socket, {EncType, InfoKey, Password, AAD, EnSalt}) when EncType =:= aes128gcm; 
        EncType =:= aes192gcm; EncType =:= aes256gcm; EncType =:= chacha20_poly1305 -> 
    Transport:setopts(Socket, [{packet, 0}, {active, false}]),
    {KeySize, _NonceSize, _TagSize} = crypto_sizes(EncType),
    {ok, DeSalt} = Transport:recv(Socket, KeySize, ?HANDSHAKE_TIMEOUT), 
    {EnKey, EnSalt} = subkey(EncType, to_binary(Password), to_binary(InfoKey), EnSalt),
    {DeKey, DeSalt} = subkey(EncType, to_binary(Password), to_binary(InfoKey), DeSalt),
    {ok, {EncType, {0, EnKey, to_binary(AAD)}, {0, DeKey, to_binary(AAD)}}}.



-spec encrypt(Transport, Socket, Data, State) -> {ok, Encrypted, NewState} | {error, Reason} when
    Transport :: module(),
    Socket    :: inet:socket(),
    Data      :: iodata(),
    State     :: any(),
    Encrypted :: iodata(),
    State     :: any(),
    NewState     :: any(),
    Reason    :: term().
%%--------------------------------------------------------------------
%% @param Data the binary to encrypt
%% @param State the state previously initialized in function periscope_crypto:handshake/3
%% @doc
%% Encrypts the given binary and returns a new encryption state
%% @end
%%--------------------------------------------------------------------
encrypt(_Transport, _Socket, Data, none) -> 
    {ok, Data, none};

%% Encrypt UDP packet without counter increment
encrypt(Transport, _Socket, Data, {_EncType, {_EnCounter, _EnKey, _EnAAD}, {_DeCounter, _DeKey, _DeAAD}}) when Transport =:= gen_udp -> 
    {ok, Data, none};

%% Encrypt TCP packet and increment counter (twice)
encrypt(Transport, _Socket, Data, {EncType, {EnCounter, EnKey, EnAAD}, DecState}) when Transport =/= gen_udp -> 
    {_KeySize, NonceSize, TagSize} = crypto_sizes(EncType),
    BinData = to_binary(Data),
    DataLen = byte_size(BinData), % TODO DataLen cannot be greater than 16#3FFFF
    IVec1 = <<EnCounter:NonceSize/integer-little-unit:8>>,
    IVec2 = <<(EnCounter + 1):NonceSize/integer-little-unit:8>>,
    Encrypted = case EncType of
        chacha20_poly1305 ->
            {Part1, Tag1} = crypto:block_encrypt(chacha20_poly1305, EnKey, IVec1, {EnAAD, <<DataLen:2/integer-big-unit:8>>}),    
            {Part2, Tag2} = crypto:block_encrypt(chacha20_poly1305, EnKey, IVec2, {EnAAD, BinData}),    
            [Part1, Tag1, Part2, Tag2];

        EncType ->
            {Part1, Tag1} = crypto:block_encrypt(aes_gcm, EnKey, IVec1, {EnAAD, <<DataLen:2/integer-big-unit:8>>, TagSize}),    
            {Part2, Tag2} = crypto:block_encrypt(aes_gcm, EnKey, IVec2, {EnAAD, BinData, TagSize}),    
            [Part1, Tag1, Part2, Tag2]
    end,
    {ok, Encrypted, {EncType, {EnCounter + 2, EnKey, EnAAD}, DecState}}.



-spec decrypt(Transport, Socket, Data, State) -> {ok, Decrypted, NewState} | {error, Reason} when
    Transport :: module(),
    Socket    :: inet:socket(),
    Data      :: iodata(),
    State     :: any(),
    Decrypted :: binary(),
    State     :: any(),
    NewState     :: any(),
    Reason    :: term().
%%--------------------------------------------------------------------
%% @param Data the binary to decrypt
%% @param State the state previously initialized in function periscope_crypto:handshake/3
%% @doc
%% Decrypts the given binary and returns a new encryption state
%% @end
%%--------------------------------------------------------------------
decrypt(_Transport, _Socket, Data, none) -> 
    {ok, Data, none};

decrypt(Transport, _Socket, Data, {_EncType, {{_EnCounter, _EnKey, _EnAAD}, {_DeCounter, _DeKey, _DeAAD}}}) when Transport =:= gen_udp -> 
    {ok, Data, none};

decrypt(Transport, Socket, Data, {EncType, EncState, {DeCounter, DeKey, DeAAD}}) when Transport =/= gen_udp -> 
    AEADType = if EncType =:= chacha20_poly1305 -> chacha20_poly1305; true -> aes_gcm end,
    {_KeySize, NonceSize, TagSize} = crypto_sizes(EncType),
    <<EncDataLen:2/binary, EncLenTag:TagSize/binary, Tail/binary>> = ensure_size(Transport, Socket, to_binary(Data), TagSize + 2),
    IVec1 = <<DeCounter:NonceSize/integer-little-unit:8>>,
    DataLenBin = crypto:block_decrypt(AEADType, DeKey, IVec1, {DeAAD, EncDataLen, EncLenTag}),
    DataLen = binary:decode_unsigned(DataLenBin, big),
    EncPayload = ensure_size(Transport, Socket, Tail, DataLen + TagSize),
    <<EncData:DataLen/binary, EncTag:TagSize/binary, Tail2/binary>> = EncPayload,
    IVec2 = <<(DeCounter + 1):NonceSize/integer-little-unit:8>>,
    Decrypted = crypto:block_decrypt(AEADType, DeKey, IVec2, {DeAAD, EncData, EncTag}),
    State = {EncType, EncState, {DeCounter + 2, DeKey, DeAAD}},
    case Tail2 of
        <<>> ->        
            {ok, [Decrypted], State};

        Tail2 ->
            {ok, Next, NewState} = decrypt(Transport, Socket, Tail2, State),
            {ok, [Decrypted | Next], NewState}   
    end.


%%%===================================================================
%%% Internal functions
%%%===================================================================


%% @private
%% @doc Generates salt 
create_salt(EncType) ->
    crypto:rand_seed(),
    {KeySize, _NonceSize, _TagSize} = crypto_sizes(EncType),
    crypto:strong_rand_bytes(KeySize).



%% @private
%% @doc Generates salt and derived subkey
subkey(EncType, Password, InfoKey) ->
    subkey(EncType, Password, InfoKey, create_salt(EncType)).

%% @private
%% @doc Generates derived subkey from the password, salt and infokey
subkey(EncType, Password, InfoKey, Salt) ->
    {KeySize, _NonceSize, _TagSize} = crypto_sizes(EncType),
    {EVP, _IV} = evp_bytestokey(Password, KeySize, KeySize),
    PRK = hkdf:extract(sha, Salt, EVP),
    Key = hkdf:expand(sha, PRK, InfoKey, KeySize),
    {Key, Salt}.



%% @private
%% @doc Returns Key size, Salt size, Nonce size and Tag size for the given cryptographic algorithm
crypto_sizes(aes128gcm) ->
    % {Key and Salt size, Nonce size, Tag size}
    {16, 12, 16}; 

crypto_sizes(aes192gcm) ->
    {24, 12, 16}; 

crypto_sizes(aes256gcm) ->
    {32, 12, 16}; 

crypto_sizes(chacha20_poly1305) ->
    {32, 12, 16}.



%% @private
%% @doc Equivalent to OpenSSL's EVP_BytesToKey() with count 1
evp_bytestokey(Password, KeySize, IvSize) ->
    evp_bytestokey(to_binary(Password), KeySize, IvSize, [], 0).

evp_bytestokey(Password, KeySize, IvSize, [], 0) ->
    Digest = crypto:hash(md5, Password),
    Acc = [Digest],
    evp_bytestokey(Password, KeySize, IvSize, Acc, iolist_size(Acc));

evp_bytestokey(_Password, KeySize, IvSize, Acc, AccSize) when AccSize >= KeySize + IvSize ->
    <<Key:KeySize/binary, IV:IvSize/binary, _/binary>> = list_to_binary(lists:reverse(Acc)),
    {Key, IV};

evp_bytestokey(Password, KeySize, IvSize, [Prev|_] = Acc, _AccSize) ->
    Digest = crypto:hash(md5, <<Prev/binary, Password/binary>>),
    NewAcc = [Digest | Acc],
    evp_bytestokey(Password, KeySize, IvSize, NewAcc, iolist_size(NewAcc)).



%% @private
%% @doc Ensure size of the binary to be loaded from socket
ensure_size(_Transport, _Socket, Binary, Size) when byte_size(Binary) >= Size -> 
    Binary;

ensure_size(Transport, Socket, Binary, Size) ->
    Transport:setopts(Socket, [{active, false}]),
    {ok, Tail} = Transport:recv(Socket, Size-byte_size(Binary), ?READ_TIMEOUT),
    <<Binary/binary, Tail/binary>>.
