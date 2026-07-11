{ pkgs, nebula }:
pkgs.testers.runNixOSTest {
  name = "nebula-mixed-daemon";

  nodes = {
    initiator = { ... }: {
      networking.firewall.allowedUDPPorts = [ 4242 ];
      environment.systemPackages = [ nebula ];
      systemd.services.nebula-mixed = {
        serviceConfig.ExecStart = "${nebula}/bin/nebula -config /var/lib/nebula-mixed/config.yml";
      };
    };
    responder = { ... }: {
      networking.firewall.allowedUDPPorts = [ 4242 ];
      environment.systemPackages = [ nebula ];
      systemd.services.nebula-mixed = {
        serviceConfig.ExecStart = "${nebula}/bin/nebula -config /var/lib/nebula-mixed/config.yml";
      };
    };
  };

  testScript = ''
    initiator.start()
    responder.start()
    initiator.wait_for_unit("multi-user.target")
    responder.wait_for_unit("multi-user.target")
    initiator.succeed("install -d /var/lib/nebula-mixed /tmp/identity")
    responder.succeed("install -d /var/lib/nebula-mixed")

    for curve in ["25519", "P256", "P384"]:
      initiator.succeed(
        f"nebula-cert ca -name {curve}-ca -curve {curve} -duration 2h "
        f"-out-crt /tmp/identity/{curve}.ca.crt -out-key /tmp/identity/{curve}.ca.key"
      )

    def make_identity(name, ip):
      for curve in ["25519", "P256", "P384"]:
        initiator.succeed(
          f"nebula-cert keygen -curve {curve} -out-key /tmp/identity/{name}.{curve}.key "
          f"-out-pub /tmp/identity/{name}.{curve}.pub"
        )
        initiator.succeed(
          f"nebula-cert sign -ca-crt /tmp/identity/{curve}.ca.crt "
          f"-ca-key /tmp/identity/{curve}.ca.key -name {name} -ip {ip}/24 "
          f"-in-pub /tmp/identity/{name}.{curve}.pub -duration 1h "
          f"-out-crt /tmp/identity/{name}.{curve}.crt"
        )

    make_identity("initiator", "10.77.0.1")
    make_identity("responder", "10.77.0.2")
    initiator.succeed("cat /tmp/identity/{25519,P256,P384}.ca.crt > /tmp/identity/ca-bundle.crt")

    for filename in initiator.succeed("find /tmp/identity -type f -printf '%f\\n'").split():
      encoded = initiator.succeed(f"base64 -w0 /tmp/identity/{filename}").strip()
      initiator.succeed(f"printf %s {encoded} | base64 -d > /var/lib/nebula-mixed/{filename}")
      responder.succeed(f"printf %s {encoded} | base64 -d > /var/lib/nebula-mixed/{filename}")

    def configure(node, name, peer, local_underlay, peer_underlay, preferences):
      node.succeed(f"cat > /var/lib/nebula-mixed/config.yml <<'EOF'\npki:\n  ca: /var/lib/nebula-mixed/ca-bundle.crt\n  cert: /var/lib/nebula-mixed/{name}.25519.crt\n  key: /var/lib/nebula-mixed/{name}.25519.key\n  p256_cert: /var/lib/nebula-mixed/{name}.P256.crt\n  p256_key: /var/lib/nebula-mixed/{name}.P256.key\n  p384_cert: /var/lib/nebula-mixed/{name}.P384.crt\n  p384_key: /var/lib/nebula-mixed/{name}.P384.key\n  curve_preferences: [{preferences}]\nstatic_host_map:\n  '{peer}': ['{peer_underlay}:4242']\nlisten:\n  host: {local_underlay}\n  port: 4242\nfirewall:\n  inbound:\n    - port: any\n      proto: any\n      host: any\n  outbound:\n    - port: any\n      proto: any\n      host: any\nEOF")

    configure(initiator, "initiator", "10.77.0.2", "192.168.1.1", "192.168.1.2", "P384, P256")
    configure(responder, "responder", "10.77.0.1", "192.168.1.2", "192.168.1.1", "P256, P384")
    responder.succeed("systemctl start nebula-mixed.service")
    initiator.succeed("systemctl start nebula-mixed.service")
    initiator.wait_until_succeeds("ping -c1 -W1 10.77.0.2", timeout=60)
    responder.wait_until_succeeds("ping -c1 -W1 10.77.0.1", timeout=60)
    initiator.wait_until_succeeds("journalctl -u nebula-mixed | grep 'Authenticated mixed-curve upgrade negotiated' | grep P384", timeout=30)
    initiator.wait_until_succeeds("journalctl -u nebula-mixed | grep ix_p384_upgrade", timeout=30)
    responder.wait_until_succeeds("journalctl -u nebula-mixed | grep ix_p384_upgrade", timeout=30)

    # A normal restart succeeds before any host or sealing state is invalidated.
    initiator.succeed("systemctl restart nebula-mixed.service")
    initiator.wait_until_succeeds("ping -c1 -W1 10.77.0.2", timeout=60)

    # A peer previously observed as capable may not silently return as stock.
    responder.succeed("sed -i '/p256_/d; /p384_/d; /curve_preferences/d' /var/lib/nebula-mixed/config.yml")
    responder.succeed("systemctl restart nebula-mixed.service")
    initiator.fail("ping -c2 -W1 10.77.0.2")
    initiator.wait_until_succeeds("journalctl -u nebula-mixed | grep 'Rejecting authenticated X25519 downgrade'", timeout=30)
  '';
}
