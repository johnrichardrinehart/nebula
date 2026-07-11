{ pkgs, nebula }:
pkgs.testers.runNixOSTest {
  name = "nebula-mixed-daemon";

  nodes = {
    initiator = { pkgs, ... }: {
      networking.firewall.allowedUDPPorts = [ 4242 ];
      virtualisation.tpm.enable = true;
      environment.systemPackages = [
        nebula
        pkgs.tpm2-tools
        pkgs.openssl
      ];
      systemd.services.nebula-mixed = {
        serviceConfig.ExecStart = "${nebula}/bin/nebula -config /var/lib/nebula-mixed/config.yml";
      };
    };
    responder = { pkgs, ... }: {
      networking.firewall.allowedUDPPorts = [ 4242 ];
      virtualisation.tpm.enable = true;
      environment.systemPackages = [
        nebula
        pkgs.tpm2-tools
        pkgs.openssl
      ];
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

    def install_tpm_identity(node, name, ip, curve, handle, point_bytes):
      alg = "ecc256:ecdh-sha256" if curve == "P256" else "ecc384:ecdh-sha384"
      attrs = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda"
      node.succeed(f"tpm2_createprimary -C o -G {alg} -a '{attrs}' -c /tmp/{curve}.ctx")
      node.succeed(f"tpm2_evictcontrol -C o -c /tmp/{curve}.ctx {handle}")
      node.succeed(f"tpm2_readpublic -c {handle} -f pem -o /tmp/{curve}.pem")
      node.succeed(f"openssl pkey -pubin -in /tmp/{curve}.pem -outform DER -out /tmp/{curve}.der")
      node.succeed(f"(echo '-----BEGIN NEBULA {curve} PUBLIC KEY-----'; tail -c {point_bytes} /tmp/{curve}.der | base64; echo '-----END NEBULA {curve} PUBLIC KEY-----') > /tmp/{name}.{curve}.pub")
      node.succeed(f"rm -f /var/lib/nebula-mixed/{name}.{curve}.crt")
      node.succeed(f"nebula-cert sign -ca-crt /var/lib/nebula-mixed/{curve}.ca.crt -ca-key /var/lib/nebula-mixed/{curve}.ca.key -name {name} -ip {ip}/24 -in-pub /tmp/{name}.{curve}.pub -duration 1h -out-crt /var/lib/nebula-mixed/{name}.{curve}.crt")
      node.succeed(f"printf 'tpm2:device=/dev/tpmrm0;handle={handle};curve={curve}' > /var/lib/nebula-mixed/{name}.{curve}.key")

    install_tpm_identity(initiator, "initiator", "10.77.0.1", "P256", "0x81010110", 65)
    install_tpm_identity(initiator, "initiator", "10.77.0.1", "P384", "0x81010111", 97)
    install_tpm_identity(responder, "responder", "10.77.0.2", "P256", "0x81010120", 65)
    install_tpm_identity(responder, "responder", "10.77.0.2", "P384", "0x81010121", 97)

    def configure(node, name, peer, local_underlay, peer_underlay, preferences):
      p256_handle = "0x81010110" if name == "initiator" else "0x81010120"
      p384_handle = "0x81010111" if name == "initiator" else "0x81010121"
      node.succeed(f"cat > /var/lib/nebula-mixed/config.yml <<'EOF'\npki:\n  ca: /var/lib/nebula-mixed/ca-bundle.crt\n  cert: /var/lib/nebula-mixed/{name}.25519.crt\n  key: /var/lib/nebula-mixed/{name}.25519.key\n  p256_cert: /var/lib/nebula-mixed/{name}.P256.crt\n  p256_key: tpm2:device=/dev/tpmrm0;handle={p256_handle};curve=P256\n  p384_cert: /var/lib/nebula-mixed/{name}.P384.crt\n  p384_key: tpm2:device=/dev/tpmrm0;handle={p384_handle};curve=P384\n  curve_preferences: [{preferences}]\nhandshakes:\n  capability_cache_path: /var/lib/nebula-mixed/capabilities.json\nstatic_host_map:\n  '{peer}': ['{peer_underlay}:4242']\nlisten:\n  host: {local_underlay}\n  port: 4242\nfirewall:\n  inbound:\n    - port: any\n      proto: any\n      host: any\n  outbound:\n    - port: any\n      proto: any\n      host: any\nEOF")

    configure(initiator, "initiator", "10.77.0.2", "192.168.1.1", "192.168.1.2", "P384, P256")
    configure(responder, "responder", "10.77.0.1", "192.168.1.2", "192.168.1.1", "P256, P384")
    responder.succeed("systemctl start nebula-mixed.service")
    initiator.succeed("systemctl start nebula-mixed.service")
    initiator.wait_until_succeeds("ping -c1 -W1 10.77.0.2", timeout=60)
    responder.wait_until_succeeds("ping -c1 -W1 10.77.0.1", timeout=60)
    initiator.wait_until_succeeds("journalctl -u nebula-mixed | grep 'Authenticated mixed-curve upgrade negotiated' | grep P384", timeout=30)
    initiator.wait_until_succeeds("journalctl -u nebula-mixed | grep ix_p384_upgrade", timeout=30)
    responder.wait_until_succeeds("journalctl -u nebula-mixed | grep ix_p384_upgrade", timeout=30)

    # Force the second implemented combination and prove a real P-256 daemon tunnel.
    initiator.succeed("sed -i 's/curve_preferences: \\[P384, P256\\]/curve_preferences: [P256]/' /var/lib/nebula-mixed/config.yml")
    responder.succeed("sed -i 's/curve_preferences: \\[P256, P384\\]/curve_preferences: [P256]/' /var/lib/nebula-mixed/config.yml")
    initiator.succeed("systemctl restart nebula-mixed.service")
    responder.succeed("systemctl restart nebula-mixed.service")
    initiator.wait_until_succeeds("ping -c1 -W1 10.77.0.2", timeout=60)
    initiator.wait_until_succeeds("journalctl -u nebula-mixed --since '-1 minute' | grep ix_p256_upgrade", timeout=30)

    # Restart the observer too: persisted history must still reject stripping.
    initiator.succeed("systemctl restart nebula-mixed.service")
    responder.succeed("sed -i '/p256_/d; /p384_/d; /curve_preferences/d' /var/lib/nebula-mixed/config.yml")
    responder.succeed("systemctl restart nebula-mixed.service")
    initiator.fail("ping -c2 -W1 10.77.0.2")
    initiator.wait_until_succeeds("journalctl -u nebula-mixed | grep 'Rejecting authenticated X25519 downgrade'", timeout=30)
  '';
}
