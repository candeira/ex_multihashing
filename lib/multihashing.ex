defmodule Multihashing do
  @moduledoc """
  Utility library to create, decode and verify IPFS multihash values. Heavily indebted to @zabirauf's Multihash.
  """

  import Multihash
  import :sha3

  @type crypto_hash_type :: :sha | :sha256 | :sha512 | :sha3 | :blake2b | :blake2s

  @hash_func_to_name %{
    :sha => :sha1,
    :sha256 => :sha2_256,
    :sha512 => :sha2_512,
    :sha3 => :sha3,
    :blake2b => :blake2b,
    :blake2s => :blake2s
  }

  @hash_name_to_func %{
    :sha1 => :sha,
    :sha2_256 => :sha256,
    :sha2_512 => :sha512,
    :sha3 => :sha3,
    :blake2b => :blake2b,
    :blake2s => :blake2s
  }

  # Error strings
  @error_unimplemented "Unimplemented hash function"
  @error_invalid_hash_function "Invalid hash function"

  @doc ~S"""
  Hash the provided `data` with the given `hash_func`, and encode the result into a multihash value.

  An optional parameter `length` allows hash digests to be
  [truncated](https://github.com/jbenet/multihash/issues/1#issuecomment-91783612).

  For drop-in compatibility with Erlang's Crypto library, Multihashing accepts both the Crypto
  and the go-multihash names for the algorithms. Thus, the following pairs of hash function names
  are equivalent: `{:sha, sha1}`, `{:sha256, :sha2_256}`, `{:sha512, "sha2_512"}`.

  ## Examples

      iex> Multihashing.hash(:sha, "Hello")
      {:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}

      iex> Multihashing.hash(:sha1, "Hello", 10)
      {:ok, <<17, 10, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>}

      iex> Multihashing.hash(:sha2_256, "Hello")
      {:ok, <<18, 32, 24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105>>}

      iex> Multihashing.hash(:sha3, "Hello", 10)
      {:ok, <<20, 10, 195, 63, 237, 225, 138, 26, 229, 61, 219, 134>>}

  An invalid `hash_func` or a `length` longer than the default of the digest length corresponding
  to the hash function will return an error

  It's not clear what an implementation should do when passed a length longer than the digest length.
  This cirumstance is [under discussion](https://github.com/jbenet/multihash/issues/16); for now,
  this library returns an error.

      iex> Multihashing.hash(:sha2_unknown, "Hello")
      {:error, "Invalid hash function"}

      iex> Multihashing.hash(:sha1, "Hello", 30)
      {:error, "Invalid truncation length"}

  The digest algorithms blake2b` and `blake2s` are still unimplemented.

      iex> Multihashing.hash(:blake2b, "Hello")
      {:error, "Unimplemented hash function"}
  """
  def hash(hash_id, data, length \\ :default)

  @spec hash(crypto_hash_type, binary, Multihash.default_integer) :: Multihash.on_encode
  def hash(hash_id, data, length) when is_binary(data) do
    with {:ok, {hash_func, hash_name}} <- get_hash_func_name_pair(hash_id),
         {:ok, digest} <- make_digest(hash_func, data),
         do: Multihash.encode(hash_name, digest, length)
  end

  @doc """
  Initialise a context for incremental hashing.

  A context can be initialised empty, by calling `hash_init/1` just with a `hash_id`.

        iex> {:ok, context} = Multihashing.hash_init(:sha1)
        iex> {:ok, context} = Multihashing.hash_update(context, "Hello")
        iex> Multihashing.hash_final(context)
        {:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}

  It can also be initialised with an optional binary `data` parameter to update the hash on, and later finalised with an optional `length` parameter.

        iex> {:ok, context} = Multihashing.hash_init(:sha1, "Hell")
        iex> {:ok, context} = Multihashing.hash_update(context, "o")
        iex> Multihashing.hash_final(context, 10)
        {:ok, <<17, 10, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>}
  """
  def hash_init(hash_id, data \\ nil)

  # @spec hash(crypto_hash_type, binary) :: :crypto.context # commented out because what type is context?
  def hash_init(hash_id, data) when is_atom(hash_id) do
    with {:ok, {hash_func, _}} <- get_hash_func_name_pair(hash_id),
         do: context_init(hash_func, data)
  end

  def hash_update(context, data) when is_binary(data) do
    context_update(context, data)
  end

  def hash_final(context, length \\ :default) do
    with {hash_func, _} <- context,
         {:ok, digest} <- context_final(context),
         {:ok, {_, hash_name}} <- get_hash_func_name_pair(hash_func),
         do: Multihash.encode(hash_name, digest, length)
  end

  @doc """
  Decode the provided multihash value to the struct %Multihash{code: , name: , length: , digest: }

      iex> Multihashing.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
      {:ok, %Multihash{name: :sha1, code: 17, length: 20, digest: <<247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}}

  iex> Multihashing.decode(<<17, 10, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>)
  {:ok, %Multihash{name: :sha1, code: 17, length: 10, digest: <<247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>}}

  Invalid multihash values will result in errors.

      iex> Multihashing.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>)
      {:error, "Invalid size"}

      iex> Multihashing.decode(<<17, 22, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 20, 21, 22>>)
      {:error, "Invalid length"}

      iex> Multihashing.decode(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
      {:error, "Invalid hash code"}

      iex> Multihashing.decode("Hello")
      {:error, "Invalid hash code"}
  """
  @spec decode(binary) :: Multihash.on_decode
  def decode(multihash) when is_binary(multihash) do
    Multihash.decode(multihash)
  end

  @doc """
  Verify that the provided multihash value and data binary match.

      iex> Multihashing.verify(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>, "Hello")
      {:ok, true}

      iex> Multihashing.verify(<<17, 10, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>, "Hello")
      {:ok, true}

      iex> Multihashing.verify(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>, "Good Bye")
      {:ok, false}

  Verifying involves a decoding step, so verifying an invalid multihash will result in errors.

      iex> Multihashing.verify(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>, "Hello")
      {:error, "Invalid size"}

      iex> Multihashing.verify(<<17, 22, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 20, 21, 22>>, "Hello")
      {:error, "Invalid length"}

      iex> Multihashing.verify(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>, "Hello")
      {:error, "Invalid hash code"}

      iex> Multihashing.verify("Hello", "Hello")
      {:error, "Invalid hash code"}
  """
  @spec verify(binary, binary) :: boolean
  def verify(multihash, data) do
    with {:ok, mh} <- Multihash.decode(multihash),
         {:ok, reencoded} <- reencode(mh, data),
         do: {:ok, reencoded == multihash}
  end


  ## PRIVATE FUNCTIONS

  # USED BY hash()

  defp get_hash_func_name_pair(hash_id) do
    func? = Map.get(@hash_name_to_func, hash_id, :func_not_found)
    name? = Map.get(@hash_func_to_name, hash_id, :name_not_found)
    case {func?, name?} do
      {:func_not_found, :name_not_found} ->  {:error, @error_invalid_hash_function}
      {:func_not_found, _} -> {:ok, {hash_id, name?}}
      {_, :name_not_found} -> {:ok, {func?, hash_id}}
      {_, _} -> {:ok, {func?, name?}}
    end
  end

  defp make_digest(hash_func, data) when is_atom(hash_func) and is_binary(data) do
    case hash_func do
      :sha -> {:ok, :crypto.hash(:sha, data)}
      :sha256 -> {:ok, :crypto.hash(:sha256, data)}
      :sha512 -> {:ok, :crypto.hash(:sha512, data)}
      :sha3 -> {:ok, :sha3.hash(512, data)}
      :blake2b -> {:error, @error_unimplemented}
      :blake2s -> {:error, @error_unimplemented}
      _ -> {:error, @error_invalid_hash_function}
    end
  end

  # USED BY hash_init(), hash_update(), hash_final()

  defp context_init(hash_func, data \\ nil) when is_atom(hash_func) do
    context? = case hash_func do
      :sha -> {:ok, :crypto.hash_init(:sha)}
      :sha256 -> {:ok, :crypto.hash_init(:sha256)}
      :sha512 -> {:ok, :crypto.hash_init(:sha512)}
      :sha3 -> {:ok, {:sha3, :sha3.hash_init(512)}}
      :blake2b -> {:error, @error_unimplemented}
      :blake2s -> {:error, @error_unimplemented}
      _ -> {:error, @error_invalid_hash_function}
    end
    case {context?, data} do
      {{:error, message}, _} -> {:error, message}
      {{:ok, context}, nil} -> {:ok, context}
      {{:ok, context}, _} -> context_update(context, data)
    end
  end

  defp context_update({hash_func, innercontext}=context, data) when is_binary(data) and is_atom(hash_func) do
    case hash_func do
      :sha -> {:ok, :crypto.hash_update(context, data)}
      :sha256 -> {:ok, :crypto.hash_update(context, data)}
      :sha512 -> {:ok, :crypto.hash_update(context, data)}
      :sha3 -> {:ok, {:sha3, :sha3.hash_update(innercontext, data)}}

      :blake2b -> {:error, @error_unimplemented}
      :blake2s -> {:error, @error_unimplemented}
      _ -> {:error, @error_invalid_hash_function}
    end
  end

  defp context_final({hash_func, innercontext} = context) do
    case hash_func do
      :sha -> {:ok, :crypto.hash_final(context)}
      :sha256 -> {:ok, :crypto.hash_final(context)}
      :sha512 -> {:ok, :crypto.hash_final(context)}
      :sha3 -> {:ok, :sha3.hash_final(innercontext)}
      :blake2b -> {:error, @error_unimplemented}
      :blake2s -> {:error, @error_unimplemented}
      _ -> {:error, @error_invalid_hash_function}
    end
  end

  ## Used by verify()

  defp reencode(%Multihash{name: name, length: length}, data) do
    Multihashing.hash(name, data, length)
  end

end

