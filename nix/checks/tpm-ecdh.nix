{
  pkgs,
  tpmclientTest,
  handshakeTest,
}:
pkgs.testers.runNixOSTest {
  name = "nebula-tpm-ecdh";

  nodes.machine = { pkgs, ... }: {
    virtualisation.tpm.enable = true;
    environment.systemPackages = [
      pkgs.tpm2-tools
      tpmclientTest
      handshakeTest
    ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -c /dev/tpmrm0")

    attributes = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda"
    machine.succeed(
      f"tpm2_createprimary -C o -G ecc256:ecdh-sha256 -a '{attributes}' -c /tmp/p256.ctx"
    )
    machine.succeed("tpm2_evictcontrol -C o -c /tmp/p256.ctx 0x81010010")
    machine.succeed(
      f"tpm2_createprimary -C o -G ecc384:ecdh-sha384 -a '{attributes}' -c /tmp/p384.ctx"
    )
    machine.succeed("tpm2_evictcontrol -C o -c /tmp/p384.ctx 0x81010011")

    tpm_env = (
      "NEBULA_TEST_TPM_URI_P256='tpm2:device=/dev/tpmrm0;handle=0x81010010;curve=P256' "
      "NEBULA_TEST_TPM_URI_P384='tpm2:device=/dev/tpmrm0;handle=0x81010011;curve=P384' "
    )
    machine.succeed(tpm_env + "tpmclient.test -test.v -test.run TestPersistentTPMECDH")
    machine.succeed(tpm_env + "handshake.test -test.v -test.run TestTPMBackedUpgradeHandshake")

    p256 = machine.succeed("tpm2_readpublic -c 0x81010010")
    p384 = machine.succeed("tpm2_readpublic -c 0x81010011")
    for output in (p256, p384):
      assert "fixedtpm" in output.lower()
      assert "fixedparent" in output.lower()
      assert "sensitivedataorigin" in output.lower()
      assert "decrypt" in output.lower()
  '';
}
