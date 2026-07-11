{
  pkgs,
  nebula,
  nebulaUpstream,
  securekeyTest,
}:
let
  unseal = pkgs.writeShellScript "nebula-unseal-x25519" ''
    set -euo pipefail
    ${pkgs.tpm2-tools}/bin/tpm2_load -C /var/lib/nebula-test/primary.ctx \
      -u /var/lib/nebula-test/sealed.pub \
      -r /var/lib/nebula-test/sealed.priv \
      -c /run/nebula-test/sealed.ctx
    ${pkgs.tpm2-tools}/bin/tpm2_startauthsession --policy-session -S /run/nebula-test/session.ctx
    ${pkgs.tpm2-tools}/bin/tpm2_policypcr -S /run/nebula-test/session.ctx -l sha256:7
    ${pkgs.tpm2-tools}/bin/tpm2_unseal -c /run/nebula-test/sealed.ctx \
      -p session:/run/nebula-test/session.ctx \
      | ${nebula}/bin/nebula-keyring -description nebula-host-key -- \
        ${nebula}/bin/nebula -config /var/lib/nebula-test/config.yml
  '';
in
pkgs.testers.runNixOSTest {
  name = "nebula-sealed-x25519";

  nodes.machine = { ... }: {
    virtualisation.tpm.enable = true;
    networking.firewall.allowedUDPPorts = [ 4242 ];
    users.groups.tss = { };
    services.udev.extraRules = ''
      KERNEL=="tpm[0-9]*", GROUP="tss", MODE="0660"
      KERNEL=="tpmrm[0-9]*", GROUP="tss", MODE="0660"
    '';
    environment.systemPackages = [
      pkgs.tpm2-tools
      nebula
      pkgs.keyutils
    ];

    systemd.services.nebula-sealed-test = {
      serviceConfig = {
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        KeyringMode = "private";
        RuntimeDirectory = "nebula-test";
        StateDirectory = "nebula-test";
        ExecStart = unseal;
        LimitCORE = 0;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        RestrictSUIDSGID = true;
        SupplementaryGroups = [ "tss" ];
      };
    };
  };

  nodes.stock = { ... }: {
    networking.firewall.allowedUDPPorts = [ 4242 ];
    environment.systemPackages = [
      nebulaUpstream
      securekeyTest
    ];
    systemd.services.nebula-stock = {
      serviceConfig = {
        ExecStart = "${nebulaUpstream}/bin/nebula -config /var/lib/nebula-stock/config.yml";
        Restart = "no";
      };
    };
  };

  testScript = ''
    machine.start()
    stock.start()
    machine.wait_for_unit("multi-user.target")
    stock.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0755 /var/lib/nebula-test")

    machine.succeed("tpm2_createprimary -C o -G rsa -g sha256 -c /var/lib/nebula-test/primary.ctx")
    machine.succeed("tpm2_pcrread sha256:7 -o /tmp/pcr.bin")
    machine.succeed(
      "tpm2_createpolicy --policy-pcr -l sha256:7 -f /tmp/pcr.bin -L /var/lib/nebula-test/policy.dat"
    )

    # The host private key travels from keygen stdout directly into TPM2_Create.
    # Only public TPM blobs and a public certificate are placed on disk.
    machine.succeed(
      "set -o pipefail; nebula-cert keygen -out-key - -out-pub /var/lib/nebula-test/host.pub "
      "| tpm2_create -C /var/lib/nebula-test/primary.ctx "
      "-L /var/lib/nebula-test/policy.dat -i - "
      "-u /var/lib/nebula-test/sealed.pub -r /var/lib/nebula-test/sealed.priv"
    )
    machine.succeed(
      "nebula-cert ca -name test -duration 1h -out-crt /var/lib/nebula-test/ca.crt "
      "-out-key /var/lib/nebula-test/ca.key"
    )
    machine.succeed(
      "nebula-cert sign -ca-crt /var/lib/nebula-test/ca.crt -ca-key /var/lib/nebula-test/ca.key "
      "-name host -ip 10.42.42.1/24 -in-pub /var/lib/nebula-test/host.pub "
      "-out-crt /var/lib/nebula-test/host.crt"
    )
    machine.succeed("nebula-cert keygen -out-key /tmp/stock.key -out-pub /tmp/stock.pub")
    machine.succeed(
      "nebula-cert sign -ca-crt /var/lib/nebula-test/ca.crt -ca-key /var/lib/nebula-test/ca.key "
      "-name stock -ip 10.42.42.2/24 -in-pub /tmp/stock.pub -out-crt /tmp/stock.crt"
    )
    machine.succeed("rm /var/lib/nebula-test/ca.key")
    machine.succeed("test ! -e /var/lib/nebula-test/host.key")
    machine.succeed("! grep -R 'NEBULA X25519 PRIVATE KEY' /var/lib/nebula-test")

    machine.succeed("cat > /var/lib/nebula-test/config.yml <<'EOF'\npki:\n  ca: /var/lib/nebula-test/ca.crt\n  cert: /var/lib/nebula-test/host.crt\n  key: keyring:nebula-host-key\nstatic_host_map:\n  '10.42.42.2': ['192.168.1.2:4242']\nlisten:\n  host: 0.0.0.0\n  port: 4242\nfirewall:\n  inbound:\n    - port: any\n      proto: any\n      host: any\n  outbound:\n    - port: any\n      proto: any\n      host: any\nEOF")
    machine.succeed("chmod -R a+rX /var/lib/nebula-test")

    stock.succeed("install -d -m 0755 /var/lib/nebula-stock")
    for source, destination in [
      ("/var/lib/nebula-test/ca.crt", "/var/lib/nebula-stock/ca.crt"),
      ("/tmp/stock.crt", "/var/lib/nebula-stock/host.crt"),
      ("/tmp/stock.key", "/var/lib/nebula-stock/host.key"),
    ]:
      encoded = machine.succeed(f"base64 -w0 {source}").strip()
      stock.succeed(f"printf %s {encoded} | base64 -d > {destination}")
    stock.succeed("cat > /var/lib/nebula-stock/config.yml <<'EOF'\npki:\n  ca: /var/lib/nebula-stock/ca.crt\n  cert: /var/lib/nebula-stock/host.crt\n  key: /var/lib/nebula-stock/host.key\nstatic_host_map:\n  '10.42.42.1': ['192.168.1.1:4242']\nlisten:\n  host: 0.0.0.0\n  port: 4242\nfirewall:\n  inbound:\n    - port: any\n      proto: any\n      host: any\n  outbound:\n    - port: any\n      proto: any\n      host: any\nEOF")
    stock.succeed("systemctl start nebula-stock.service")

    machine.succeed("systemctl start nebula-sealed-test.service")
    machine.wait_for_unit("nebula-sealed-test.service")
    machine.sleep(1)
    machine.succeed("systemctl is-active nebula-sealed-test.service")
    machine.succeed("systemctl show nebula-sealed-test -p DynamicUser -p KeyringMode -p LimitCORE | grep -E 'DynamicUser=yes|KeyringMode=private|LimitCORE=0'")
    # Root's keyring cannot locate the service-scoped key, and Nebula revokes it
    # immediately after loading even within the inherited service keyring.
    machine.succeed("! keyctl search @s user nebula-host-key")
    machine.succeed("test ! -e /run/nebula-test/host.key")
    machine.wait_until_succeeds("ping -c1 -W1 10.42.42.2", timeout=60)
    stock.wait_until_succeeds("ping -c1 -W1 10.42.42.1", timeout=60)
    stock.succeed("systemctl is-active nebula-stock.service")
    # This node has no TPM; exercise the mlocked, non-dumpable encrypted-memory fallback.
    stock.succeed("securekey.test -test.v")

    machine.succeed("systemctl restart nebula-sealed-test.service")
    machine.sleep(1)
    machine.succeed("systemctl is-active nebula-sealed-test.service")
    machine.wait_until_succeeds("ping -c1 -W1 10.42.42.2", timeout=60)
    machine.succeed("systemctl stop nebula-sealed-test.service")
    machine.succeed("digest=$(printf changed | sha256sum | cut -d' ' -f1); tpm2_pcrextend 7:sha256=$digest")
    machine.succeed("systemctl start nebula-sealed-test.service")
    machine.wait_until_succeeds("systemctl is-failed nebula-sealed-test.service")
  '';
}
