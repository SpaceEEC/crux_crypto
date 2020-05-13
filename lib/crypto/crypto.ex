defmodule Crux.Crypto do
  @moduledoc """
    Module providing libsodium bindings.
  """

  @on_load :load_nifs

  @doc false
  def load_nifs() do
    "#{__DIR__}/../../src/crypto"
    |> Path.expand()
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @doc """
  Generates `size` unpredictable bytes as a binary.
  """
  @spec randombytes_buf(size :: non_neg_integer()) :: binary()
  def randombytes_buf(_size) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc """
  Encrypts a message using a key and a nonce.
  """
  @spec crypto_secretbox_easy(message :: binary(), key :: binary(), nonce :: binary()) :: binary()
  def crypto_secretbox_easy(_message, _key, _nonce) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc """
  Decrypts a message using a key and a nonce.
  """
  @spec crypto_secretbox_open_easy(message :: binary(), key :: binary(), nonce :: binary()) ::
          binary()
  def crypto_secretbox_open_easy(_message, _key, _nonce) do
    :erlang.nif_error(:nif_not_loaded)
  end
end
