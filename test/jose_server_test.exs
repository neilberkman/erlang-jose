defmodule JOSEServerTest do
  use ExUnit.Case, async: false

  test "selects native Ed448 without crypto fallback or optional dependencies" do
    if native_ed448_supported?() do
      ebin = Application.app_dir(:jose, "ebin")

      expression = """
      ok = application:load({application, jose, [
        {description, "JOSE isolated native Ed448 test"},
        {vsn, "test"},
        {mod, {jose_app, []}},
        {registered, []},
        {applications, [kernel, stdlib, crypto, asn1, public_key]},
        {modules, []}
      ]}),
      ok = application:set_env(jose, crypto_fallback, false),
      {ok, _} = application:ensure_all_started(jose),
      jose_curve448_crypto = jose:curve448_module(),
      jose_sha3_unsupported = jose:sha3_module(),
      {PublicKey, SecretKey} = jose_curve448:eddsa_keypair(),
      Message = <<\"native-ed448\">>,
      Signature = jose_curve448:ed448_sign(Message, SecretKey),
      true = jose_curve448:ed448_verify(Signature, Message, PublicKey),
      PublicKeys = proplists:get_value(public_keys, jose_jwa:crypto_supports()),
      true = lists:member(ed448, PublicKeys),
      false = lists:member(ed448ph, PublicKeys),
      false = lists:member(ed25519ph, PublicKeys),
      ok = jose:crypto_fallback(true),
      FallbackPublicKeys = proplists:get_value(public_keys, jose_jwa:crypto_supports()),
      true = lists:member(ed448ph, FallbackPublicKeys),
      true = lists:member(ed25519ph, FallbackPublicKeys),
      halt(0).
      """

      {output, status} =
        System.cmd(
          System.find_executable("erl"),
          [
            "-noshell",
            "-noinput",
            "-pa",
            ebin,
            "-eval",
            expression
          ],
          env: [{"ERL_LIBS", nil}],
          stderr_to_stdout: true
        )

      assert status == 0, output
    end
  end

  defp native_ed448_supported? do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed448)
    message = "native-ed448-capability-check"
    signature = :crypto.sign(:eddsa, :none, message, [private_key, :ed448])
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed448])
  rescue
    _ -> false
  catch
    _, _ -> false
  end
end
