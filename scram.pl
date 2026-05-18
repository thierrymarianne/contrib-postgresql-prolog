:- module(scram, [do_scram_sha_256_after_offer/3]).

:- use_module(library(charsio)).
:- use_module(library(crypto)).
:- use_module(library(lists)).
:- use_module(library(format)).
:- use_module(library(dcgs)).

:- use_module('messages', [
    auth_method/2,
    sasl_initial_response_message/3,
    sasl_response_message/2
]).

% Reads bytes from Stream the same way postgresql.pl get_bytes/2 does.
:- use_module('types', [int32/2]).

% scram_sha_256_authenticate(+Stream, +User, +Password)
%
% Performs SCRAM-SHA-256 SASL authentication on a Postgres wire-protocol
% Stream that has just received an R(10) AuthenticationSASL message.
% Caller is expected to read the next R(0) AuthenticationOk and proceed
% to ReadyForQuery.
%
% References:
%   - RFC 5802 (SCRAM)
%   - RFC 7677 (SCRAM-SHA-256)
%   - PostgreSQL protocol: SASL Authentication
% Entry point used when R(10) AuthenticationSASL has already been read
% and decoded by the dispatcher. We start by sending the client-first
% SASLInitialResponse and run the rest of the handshake.
do_scram_sha_256_after_offer(Stream, User, Password) :-
    % --- client-first-message ---
    client_nonce_chars(ClientNonce),
    append("n=", User, NUser0),
    append(NUser0, ",r=", NUser1),
    append(NUser1, ClientNonce, ClientFirstBare),
    append("n,,", ClientFirstBare, ClientFirst),

    sasl_initial_response_message("SCRAM-SHA-256", ClientFirst, InitBytes),
    put_bytes(Stream, InitBytes),

    % --- server-first-message in R(11) ---
    get_message_bytes(Stream, ContinueMsg),
    auth_method(ContinueMsg, sasl_continue(ServerFirstBytes)),
    chars_utf8bytes(ServerFirst, ServerFirstBytes),
    parse_server_first(ServerFirst, ServerNonce, SaltBytes, Iterations),

    % Sanity: server must echo our client nonce as a prefix.
    (   append(ClientNonce, _, ServerNonce)
    ->  true
    ;   throw(scram_invalid_server_nonce) ),

    % --- compute keys ---
    chars_utf8bytes(Password, PasswordBytes),
    pbkdf2_hmac_sha256(PasswordBytes, SaltBytes, Iterations, 32, SaltedPassword),

    hmac_sha256(SaltedPassword, "Client Key", ClientKey),
    sha256_bytes(ClientKey, StoredKey),

    % gs2-header "n,," in base64 is "biws"
    GS2HeaderB64 = "biws",
    append("c=", GS2HeaderB64, CHead),
    append(CHead, ",r=", CHead1),
    append(CHead1, ServerNonce, ClientFinalWithoutProof),

    % AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
    append(ClientFirstBare, ",", AM0),
    append(AM0, ServerFirst, AM1),
    append(AM1, ",", AM2),
    append(AM2, ClientFinalWithoutProof, AuthMessageChars),

    hmac_sha256(StoredKey, AuthMessageChars, ClientSignature),
    bytes_xor(ClientKey, ClientSignature, ClientProof),

    bytes_to_chars(ClientProof, ClientProofChars),
    chars_base64(ClientProofChars, ClientProofB64, []),

    append(ClientFinalWithoutProof, ",p=", CF0),
    append(CF0, ClientProofB64, ClientFinal),

    sasl_response_message(ClientFinal, FinalBytes),
    put_bytes(Stream, FinalBytes),

    % --- server-final-message in R(12) ---
    get_message_bytes(Stream, FinalMsg),
    auth_method(FinalMsg, sasl_final(ServerFinalBytes)),
    chars_utf8bytes(ServerFinal, ServerFinalBytes),
    parse_server_final(ServerFinal, ServerSigB64),
    chars_base64(ServerSigChars, ServerSigB64, []),
    chars_to_bytes(ServerSigChars, ServerSigBytes),

    % Verify server signature
    hmac_sha256(SaltedPassword, "Server Key", ServerKey),
    hmac_sha256(ServerKey, AuthMessageChars, ExpectedServerSig),

    (   ServerSigBytes == ExpectedServerSig
    ->  true
    ;   throw(scram_server_signature_mismatch) ).


% ---------------------------------------------------------------- helpers

% Read a single Postgres protocol message from Stream:
%   [TypeByte, L3, L2, L1, L0, Body...]
% where the int32(L3..L0) length includes itself but not the type byte.
get_message_bytes(Stream, Bytes) :-
    get_byte(Stream, BType),
    get_byte(Stream, B3),
    get_byte(Stream, B2),
    get_byte(Stream, B1),
    get_byte(Stream, B0),
    int32(Length, [B3,B2,B1,B0]),
    Remaining is Length - 4,
    get_n_bytes(Stream, Remaining, Body),
    append([BType,B3,B2,B1,B0], Body, Bytes).

get_n_bytes(_, 0, []) :- !.
get_n_bytes(Stream, N, [B|Bs]) :-
    N > 0,
    get_byte(Stream, B),
    N1 is N - 1,
    get_n_bytes(Stream, N1, Bs).

put_bytes(_, []).
put_bytes(Stream, [B|Bs]) :-
    put_byte(Stream, B),
    put_bytes(Stream, Bs).

% A printable-ASCII nonce: 18 random bytes base64-encoded (24 chars, no '/').
client_nonce_chars(Nonce) :-
    crypto_n_random_bytes(18, RandBytes),
    bytes_to_chars(RandBytes, RandChars),
    chars_base64(RandChars, NonceWithMaybeSlash, [padding(false), charset(url)]),
    Nonce = NonceWithMaybeSlash.

bytes_to_chars([], []).
bytes_to_chars([B|Bs], [C|Cs]) :- char_code(C, B), bytes_to_chars(Bs, Cs).

chars_to_bytes([], []).
chars_to_bytes([C|Cs], [B|Bs]) :- char_code(C, B), chars_to_bytes(Cs, Bs).

% bytes_xor(+As, +Bs, -Cs): C[i] = A[i] xor B[i].
bytes_xor([], [], []).
bytes_xor([A|As], [B|Bs], [C|Cs]) :-
    C is xor(A, B),
    bytes_xor(As, Bs, Cs).

% sha256_bytes(+InputBytes, -OutputBytes): SHA-256 over bytes -> bytes.
sha256_bytes(InputBytes, OutputBytes) :-
    bytes_to_chars(InputBytes, InputChars),
    crypto_data_hash(InputChars, Hex, [algorithm(sha256), encoding(octet)]),
    hex_bytes(Hex, OutputBytes).

% hmac_sha256(+KeyBytes, +DataChars, -MacBytes)
% Data is taken as UTF-8 chars; with encoding(octet) we feed octet-chars.
hmac_sha256(KeyBytes, DataChars, MacBytes) :-
    (   data_is_bytes(DataChars)
    ->  bytes_to_chars(DataChars, OctetChars)
    ;   OctetChars = DataChars ),
    crypto_data_hash(OctetChars, Hex, [algorithm(sha256), hmac(KeyBytes), encoding(octet)]),
    hex_bytes(Hex, MacBytes).

% Heuristic: if the head is an integer 0..255, treat as a byte list; otherwise chars.
data_is_bytes([H|_]) :- integer(H), H >= 0, H =< 255.

% pbkdf2_hmac_sha256(+PasswordBytes, +SaltBytes, +Iterations, +DkLen, -DK)
% RFC 8018. For our use, DkLen=32 (one block).
pbkdf2_hmac_sha256(Password, Salt, Iterations, 32, DK) :-
    int32_be_bytes(1, IndexBytes),
    append(Salt, IndexBytes, FirstBlockInput),
    hmac_sha256(Password, FirstBlockInput, U1),
    pbkdf2_iterate(Password, U1, U1, Iterations, 1, DK).

pbkdf2_iterate(_, _, Acc, MaxIter, MaxIter, Acc) :- !.
pbkdf2_iterate(Password, Prev, Acc, MaxIter, I, DK) :-
    I < MaxIter,
    hmac_sha256(Password, Prev, Next),
    bytes_xor(Acc, Next, Acc1),
    I1 is I + 1,
    pbkdf2_iterate(Password, Next, Acc1, MaxIter, I1, DK).

% Big-endian uint32 encoding.
int32_be_bytes(N, [B3,B2,B1,B0]) :-
    B0 is N /\ 255,
    B1 is (N >> 8) /\ 255,
    B2 is (N >> 16) /\ 255,
    B3 is (N >> 24) /\ 255.

% parse_server_first(+Chars, -CombinedNonce, -SaltBytes, -Iterations)
% Format: "r=<nonce>,s=<base64-salt>,i=<iter>"  (the m= extension is ignored if present.)
parse_server_first(Chars, Nonce, SaltBytes, Iterations) :-
    split_on(Chars, ',', Parts),
    member(NoncePart, Parts), append("r=", Nonce, NoncePart), !,
    member(SaltPart, Parts), append("s=", SaltB64, SaltPart), !,
    member(IterPart, Parts), append("i=", IterChars, IterPart), !,
    chars_base64(SaltChars, SaltB64, []),
    chars_to_bytes(SaltChars, SaltBytes),
    number_chars(Iterations, IterChars).

% parse_server_final(+Chars, -ServerSigB64) when success.
% Throws if server reported an error (e=<error>).
parse_server_final(Chars, ServerSigB64) :-
    split_on(Chars, ',', Parts),
    (   member(EPart, Parts), append("e=", Err, EPart)
    ->  throw(scram_server_error(Err))
    ;   true ),
    member(VPart, Parts), append("v=", ServerSigB64, VPart), !.

% split_on(+Chars, +SepChar, -Parts): split a char list on a given char.
split_on(Chars, Sep, [Part|Rest]) :-
    append(Part, [Sep|Tail], Chars),
    \+ member(Sep, Part),
    !,
    split_on(Tail, Sep, Rest).
split_on(Chars, _, [Chars]).
