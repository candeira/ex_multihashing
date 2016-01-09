Multihashing
==
 
[![Build Status](https://semaphoreci.com/api/v1/projects/92fa443d-5918-47a4-8de3-7f00b31c4d86/650128/badge.svg)](https://semaphoreci.com/candeira/ex_multihashing)      
[![Build Status](https://api.travis-ci.org/candeira/ex_multihashing.svg?branch=master)](https://travis-ci.org/candeira/ex_multihashing)
[![Inline docs](http://inch-ci.org/github/candeira/ex_multihashing.svg)](http://inch-ci.org/github/candeira/ex_multihashing)

[Multihashing](https://github.com/jbenet/js-multihashing) implementation in Elixir

Multihashing is a port of Juan Benet's [js-multihashing](https://github.com/jbenet/js-multihashing) library.

It makes extensive use of Zohaib Rauf's original [ex_multihash](https://github.com/zabirauf/ex_multihash) library, as well as learning a few tricks from it (thanks!).

# Rationale for this library
Values are generally read more often than written, so the most performed operation on multihashes will be verification via the sequence: 1. Obtain multihash > 2. Request blob > 3. Compare that multihash and blob match. So we add a verify() function.

The second most performed operation will be creating hashes. Hashes will only be decoded for verification and fetching, but someone has to hash the values for new data added to the IPFS network, right? We should make creating hashes as easy as possible.

The high level library should also expose a decode function, so there is no reason to import the lower level Multihash library.

In addition, **ex_multihashing** is opinionated about the following principles:
  - Adhere to the Erlang :crypto interface:
      - Users of Erlang should be able to create multihashes using `Multihashing.hash/2`, `Multihashing.hash_init/1`, `Multihashing.hash_update/2` and `Multihashing.hash_final/1`. Using those functions from the Erlang's Crypto module yields a digest, and using them from the present Multihashing module yields the corresponding multihash digest. This allows using `Multihashing.hash/2` etc. as a drop-in replacement for `:crypto.hash/2`.
      - Users should be able to verify a multihash using `Multihashing.verify/2`, mirroring how they can verify a signature using `:crypto.verify/5`.
  - Extend the Erlang crypto interface:
      - Add `Multihashing.decode/1`, which will unpack a multihash value into a multihash struct.
      - Through Elixir optional parameters, the module exposes `hash/3` as well as `hash/2`, and `hash_final/2` as well as `hash_final/1`. The extra parameter is an optional `length` parameter. The go-multihash reference implementation allows truncating digests by passing a length parameter to the hashing functions ([rationale](https://github.com/jbenet/multihash/issues/1)), so this implementation does the same to allow for verifying hashes generated by [go-multihash](https://github.com/jbenet/go-multihash/).
  - Hide the implementation details not relevant to most users:
      - For example, there is no scenario where regular library users need to get at `Multihash.encode/2`. Users can create hashes with `hash/2`, verify them with `verify/2` and unpack them with `decode/1`. The rest is internals.
  - In general, when equivalent functionality is provided, this library follows the Erlang interface. When added functionality is required, it adds methods equivalent to those in the go-multihash interface.
  - Note that, in order to truncate via the length parameter, the present Multihashing library depends on a private fork of @zabirauf's ex_multihash. This may change in the future, and the change will be reflected in this documentation.

The present repo is an example of README-driven development. At present, this is all in flux and very much not ready for production.

## Roadmap:

- [x] Write this README
- [x] Add required changes in API to upstream Multihash (lengh parameter for truncation)
    - [x] Write README (because we're doing README-driven development)
    - [x] Write tests for new API changes to Multihash
    - [x] Write code that passes the new API tests
- [x] Crib from @zabirauf's setup:
    - [x] Libraries to install (dialyzer, monad) and why
    - [x] Figure out CI 
- [x] Add function stubs and tests for the Multihashing API
- [x] Implement new API for existing hashing algorithms (sha1, sha2-256, sha2-512), with {:ok, value} wrapping
    - [x] hash()
    - [x] decode()
    - [x] verify()
- [x] Rewrite/refactor the above to avoid depending on Monad.Error, use 1.2's `with` special form instead. (thanks, @chrismccord!)
- [x] :crypto compat: add incremental encoding via the `hash_init/_update/_final` suite.
- [ ] :crypto compat: a Multihashing.MultihashCrypto module that exposes unwrapped values and throws exceptions instead of returning `{:error, message}`
- [ ] Add new test data for missing hashing algorithms (sha-3, blake2b, blake2s)
    - [ ] Generate the data and also add it to other projects (go-ipfs, py-ipfs) if it's not there
    - [ ] Figure out sharness and try and put them in there too
- [ ] Add missing hashing algorithms (sha-3, blake2b, blake2s) for which libraries can be found
    - [x] sha3 added using the github.com/szktty/erlang-sha3 NIF library
- [ ] Add missing hashing algorithms (sha-3, blake2b, blake2s) for which libraries can't be found
    - [ ] Figure out which implementations exist, both in Erlang and C.
    - [ ] Figure out how to do FFI from Elixir to C implementations of blake/sha3
    - [ ] Possibly wrap everything in its own `Crypto_plus` module that extends :crypto with the new algorithms.
- [ ] Write presentation for Elixir Meetup in Februrary
    - [ ] Make table of library equivalence between Erlang/Python/Ruby
- [ ] Known issues:
    - [ ] sha3 library only does all-at-once hashing, but not incremental hashing through hash_init/update/final.

This is very granular so I always have a next task to work on.

# How to use it

## (Multi-)Hashing
Hash the provided `data` with the given `hash_func`, and encode the result into a multihash value.

An optional parameter `length` allows hash digests to be [truncated](https://github.com/jbenet/multihash/issues/1#issuecomment-91783612).

For drop-in compatibility with Erlang's Crypto library, Multihashing accepts both the Crypto and the go-multihash names for the algorithms. Thus, the following pairs of hash function names are equivalent: `{:sha, sha1}`, `{:sha256, :sha2_256}`, `{:sha512, "sha2_512"}`.

### Examples

```
iex> Multihashing.hash(:sha1, "Hello")
{:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}

iex> Multihashing.hash(:sha1, "Hello", 10)
{:ok, <<17, 10, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>}

iex> Multihashing.hash(:sha2_256, "Hello")
{:ok, <<18, 32, 24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105>>}

iex> Multihashing.hash(:sha3, "Hello", 10)
{:ok, <<20, 10, 195, 63, 237, 225, 138, 26, 229, 61, 219, 134>>}

iex> {:ok, context} = Multihashing.hash_init(:sha1)
iex> {:ok, context} = Multihashing.hash_update(context, "Hello")
iex> Multihashing.hash_final(context)
{:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}
```

Note that Multihashing's API is a superset of Erlang's Crypto's, so it allows partial initialisation of contexts in the case of `hash_init`, and truncation in the case of `hash_final`.

```
iex> context = Multihashing.hash_init(:sha1, "Hell")
iex> Multihashing.hash_update(context, "o")
iex> Multihashing.hash_final(context, 10)
{:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>}
```

An invalid `hash_func` or a `length` longer than the default of the digest length corresponding to the hash function will return an error

It's not clear what an implementation should do when passed a length longer than the digest length. This cirumstance is [under discussion](https://github.com/jbenet/multihash/issues/16); for the moment present this library returns an error.

### Examples

```
iex> Multihashing.hash(:sha2_unknow, :crypto.hash(:sha, "Hello"))
{:error, "Invalid hash function"}

iex> Multihashing.hash(:sha, "Hello", 30)
{:error, "Invalid digest length"}
```

## Decoding

Decode the provided multihash value to the struct %Multihash{code: , name: , length: , digest: }

### Examples

```
iex> Multihashing.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:ok, %Multihash{name: "sha1", code: 17, length: 20, digest: <<247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}}
```

Invalid multihash values will result in errors.

### Examples

```
iex> Multihashing.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>)
{:error, "Invalid digest length"}

iex> Multihashing.decode(<<17, 22, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 20, 21, 22>>)
{:error, "Invalid digest length"}

iex> Multihashing.decode(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:error, "Invalid hash code"}

iex> Multihashing.decode("Hello")
{:error, "Invalid hash code"}
```

## Verifying

Verify that the provided multihash value and data binary match.

### Examples

```
iex> Multihashing.verify(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>, "Hello")
true

iex> Multihashing.verify(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>, "Good Bye")
false
```

Verifying involves a decoding step, so verifying an invalid multihash will result in errors.

### Examples

```
iex> Multihashing.verify(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>, "Hello")
{:error, "Invalid digest length"}

iex> Multihashing.verify(<<17, 22, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 20, 21, 22>>, "Hello")
{:error, "Invalid digest length}

iex> Multihashing.verify(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>, "Hello")
{:error, "Invalid hash code"}

iex> Multihashing.verify("Hello", "Hello")
{:error, "Invalid hash code"}
```

# Contributors
[Javier Candeira](https://github.com/candeira)

# License
MIT
