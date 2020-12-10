defmodule Crux.CryptoTest do
  use ExUnit.Case, async: true
  doctest Crux.Crypto

  describe "randombytes_buf/1" do
    test "invalid size type randombytes_buf/1 raises ArgumentError" do
      assert_raise ArgumentError, fn ->
        Crux.Crypto.randombytes_buf(nil)
      end
    end

    test "negative number raises ArgumentError" do
      assert_raise ArgumentError, fn ->
        Crux.Crypto.randombytes_buf(-1)
      end
    end

    test "0 returns empty binary" do
      assert "" === Crux.Crypto.randombytes_buf(0)
    end

    test "size of 48 returns a binary with a byte size of 48" do
      assert byte_size(Crux.Crypto.randombytes_buf(48)) === 48
    end
  end

  describe "crypto_secretbox_easy/3" do
    test "invalid nonce type raises ArgumentError" do
      assert_raise ArgumentError, ~r/:nonce/, fn ->
        Crux.Crypto.crypto_secretbox_easy(
          "message",
          String.duplicate("k", 32),
          nil
        )
      end
    end

    test "invalid key type raises ArgumentError" do
      assert_raise ArgumentError, ~r/:key/, fn ->
        Crux.Crypto.crypto_secretbox_easy(
          "message",
          nil,
          String.duplicate("n", 24)
        )
      end
    end

    test "invalid message type raises ArgumentError" do
      assert_raise ArgumentError, ~r/:message/, fn ->
        Crux.Crypto.crypto_secretbox_easy(
          nil,
          String.duplicate("k", 32),
          String.duplicate("n", 24)
        )
      end
    end

    test "invalid nonce length raises ArgumentError" do
      assert_raise ArgumentError, ~r/:noncebytes/, fn ->
        Crux.Crypto.crypto_secretbox_easy(
          "message",
          String.duplicate("k", 32),
          "nonce_too_short"
        )
      end
    end

    test "invalid key length raises ArgumentError" do
      assert_raise ArgumentError, ~r/:keybytes/, fn ->
        Crux.Crypto.crypto_secretbox_easy(
          "message",
          "key_too_short",
          String.duplicate("n", 24)
        )
      end
    end

    test "valid args do not raise" do
      Crux.Crypto.crypto_secretbox_easy(
        "message",
        String.duplicate("k", 32),
        String.duplicate("n", 24)
      )
    end

    test "returns valid encrypted data" do
      message = "this is a secret message!"

      key =
        <<245, 246, 193, 69, 192, 8, 166, 203, 250, 164, 224, 207, 241, 103, 31, 148, 42, 22, 145,
          89, 151, 139, 146, 187, 48, 86, 216, 25, 243, 109, 61, 118>>

      nonce =
        <<242, 39, 134, 68, 29, 67, 102, 206, 98, 61, 34, 235, 207, 194, 112, 168, 144, 243, 50,
          175, 158, 56, 40, 5>>

      data =
        Crux.Crypto.crypto_secretbox_easy(
          message,
          key,
          nonce
        )

      expected =
        <<170, 107, 31, 42, 166, 178, 53, 53, 158, 76, 209, 249, 165, 200, 253, 40, 254, 204, 129,
          147, 176, 215, 116, 190, 164, 66, 96, 94, 93, 11, 173, 197, 145, 76, 89, 93, 167, 238,
          197, 117, 243>>

      assert data === expected
    end
  end

  describe "crypto_secretbox_open_easy/3" do
    test "invalid nonce type raises ArgumentError" do
      assert_raise ArgumentError, ~r/:nonce/, fn ->
        Crux.Crypto.crypto_secretbox_open_easy(
          String.duplicate("m", 16),
          String.duplicate("k", 32),
          nil
        )
      end
    end

    test "invalid key type raises ArgumentError" do
      assert_raise ArgumentError, ~r/:key/, fn ->
        Crux.Crypto.crypto_secretbox_open_easy(
          String.duplicate("m", 16),
          nil,
          String.duplicate("n", 24)
        )
      end
    end

    test "invalid message type raises ArgumentError" do
      assert_raise ArgumentError, ~r/:message/, fn ->
        Crux.Crypto.crypto_secretbox_open_easy(
          nil,
          String.duplicate("k", 32),
          String.duplicate("n", 24)
        )
      end
    end

    test "invalid nonce length raises ArgumentError" do
      assert_raise ArgumentError, ~r/:noncebytes/, fn ->
        Crux.Crypto.crypto_secretbox_open_easy(
          String.duplicate("m", 16),
          String.duplicate("k", 32),
          "nonce_too_short"
        )
      end
    end

    test "invalid key length raises ArgumentError" do
      assert_raise ArgumentError, ~r/:keybytes/, fn ->
        Crux.Crypto.crypto_secretbox_open_easy(
          String.duplicate("m", 16),
          "key_too_short",
          String.duplicate("n", 24)
        )
      end
    end

    test "invalid message length raises ArgumentError" do
      assert_raise ArgumentError, ~r/:messagebytes/, fn ->
        Crux.Crypto.crypto_secretbox_open_easy(
          "message_to_shor",
          String.duplicate("k", 32),
          String.duplicate("n", 24)
        )
      end
    end

    test "valid args do not raise" do
      Crux.Crypto.crypto_secretbox_open_easy(
        String.duplicate("m", 16),
        String.duplicate("k", 32),
        String.duplicate("n", 24)
      )
    end

    test "invalid data returns :error" do
      encrypted_message =
        <<170, 107, 31, 42, 166, 178, 53, 53, 158, 76, 209, 249, 165, 200, 253, 40, 254, 204, 129,
          147, 176, 215, 116, 190, 164, 66, 96, 94, 93, 11, 173, 197, 145, 76, 89, 93, 167, 238,
          197, 117, 243>>

      key =
        <<245, 246, 193, 69, 192, 8, 166, 203, 250, 164, 224, 207, 241, 103, 31, 148, 42, 22, 145,
          89, 151, 139, 146, 187, 48, 86, 216, 25, 243, 109, 61, 118>>

      nonce =
        <<242, 39, 134, 68, 29, 67, 102, 206, 98, 61, 34, 235, 207, 194, 112, 168, 144, 243, 50,
          175, 158, 56, 40, 6>>

      assert :error =
               Crux.Crypto.crypto_secretbox_open_easy(
                 encrypted_message,
                 key,
                 nonce
               )
    end

    test "returns valid encrypted data" do
      encrypted_message =
        <<170, 107, 31, 42, 166, 178, 53, 53, 158, 76, 209, 249, 165, 200, 253, 40, 254, 204, 129,
          147, 176, 215, 116, 190, 164, 66, 96, 94, 93, 11, 173, 197, 145, 76, 89, 93, 167, 238,
          197, 117, 243>>

      key =
        <<245, 246, 193, 69, 192, 8, 166, 203, 250, 164, 224, 207, 241, 103, 31, 148, 42, 22, 145,
          89, 151, 139, 146, 187, 48, 86, 216, 25, 243, 109, 61, 118>>

      nonce =
        <<242, 39, 134, 68, 29, 67, 102, 206, 98, 61, 34, 235, 207, 194, 112, 168, 144, 243, 50,
          175, 158, 56, 40, 5>>

      assert {:ok, data} =
               Crux.Crypto.crypto_secretbox_open_easy(
                 encrypted_message,
                 key,
                 nonce
               )

      expected = "this is a secret message!"

      assert data === expected
    end
  end

  describe "crypto_sign_verify_detached/2" do
    test "invalid message type raises" do
      assert_raise ArgumentError, ~r/:message/, fn ->
        Crux.Crypto.crypto_sign_verify_detached(
          nil,
          String.duplicate("s", 64),
          String.duplicate("k", 32)
        )
      end
    end

    test "invalid signature type raises" do
      assert_raise ArgumentError, ~r/:signature/, fn ->
        Crux.Crypto.crypto_sign_verify_detached(
          "messsage",
          nil,
          String.duplicate("k", 32)
        )
      end
    end

    test "invalid signature length raises" do
      assert_raise ArgumentError, ~r/:signaturebytes/, fn ->
        Crux.Crypto.crypto_sign_verify_detached(
          "messsage",
          "signature_too_short",
          String.duplicate("k", 32)
        )
      end
    end

    test "invalid public_key type raises" do
      assert_raise ArgumentError, ~r/:public_key/, fn ->
        Crux.Crypto.crypto_sign_verify_detached(
          "messsage",
          String.duplicate("s", 64),
          nil
        )
      end
    end

    test "invalid public_key length raises" do
      assert_raise ArgumentError, ~r/:public_keybytes/, fn ->
        Crux.Crypto.crypto_sign_verify_detached(
          "messsage",
          String.duplicate("s", 64),
          "key_too_short"
        )
      end
    end

    test "fails with edited message" do
      message = <<105, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100>>

      signature =
        <<106, 87, 37, 244, 1, 119, 163, 161, 58, 187, 183, 235, 99, 74, 71, 183, 210, 106, 71,
          176, 135, 121, 1, 157, 89, 202, 101, 197, 126, 0, 38, 237, 127, 144, 107, 180, 155, 160,
          117, 161, 66, 246, 84, 177, 117, 177, 98, 170, 251, 179, 232, 246, 200, 231, 240, 93,
          75, 132, 14, 81, 32, 208, 18, 12>>

      public_key =
        <<6, 70, 18, 121, 182, 147, 145, 131, 189, 89, 217, 8, 248, 48, 50, 178, 234, 81, 113, 39,
          107, 33, 21, 74, 93, 91, 232, 41, 97, 13, 78, 195>>

      assert :error = Crux.Crypto.crypto_sign_verify_detached(message, signature, public_key)
    end

    test "works for matching message, signature, and public key" do
      message = <<104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100>>

      signature =
        <<106, 87, 37, 244, 1, 119, 163, 161, 58, 187, 183, 235, 99, 74, 71, 183, 210, 106, 71,
          176, 135, 121, 1, 157, 89, 202, 101, 197, 126, 0, 38, 237, 127, 144, 107, 180, 155, 160,
          117, 161, 66, 246, 84, 177, 117, 177, 98, 170, 251, 179, 232, 246, 200, 231, 240, 93,
          75, 132, 14, 81, 32, 208, 18, 12>>

      # secret_key =
      #   <<107, 112, 201, 110, 113, 98, 182, 68, 44, 69, 225, 197, 46, 8, 104, 221, 182, 64, 159,
      #     154, 35, 199, 32, 42, 99, 27, 226, 142, 88, 34, 10, 243, 6, 70, 18, 121, 182, 147, 145,
      #     131, 189, 89, 217, 8, 248, 48, 50, 178, 234, 81, 113, 39, 107, 33, 21, 74, 93, 91, 232,
      #     41, 97, 13, 78, 195>>

      public_key =
        <<6, 70, 18, 121, 182, 147, 145, 131, 189, 89, 217, 8, 248, 48, 50, 178, 234, 81, 113, 39,
          107, 33, 21, 74, 93, 91, 232, 41, 97, 13, 78, 195>>

      assert :ok = Crux.Crypto.crypto_sign_verify_detached(message, signature, public_key)
    end
  end
end
