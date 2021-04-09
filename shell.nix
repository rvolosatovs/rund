{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    openssl
    stress

    (
      pkgs.writeShellScriptBin "serve" ''
        set -e
        ${pkgs.fd}/bin/fd --glob '*.go' cmd/rund cmd/internal pkg/job pkg/rund | ${pkgs.entr}/bin/entr -rs '${pkgs.go}/bin/go build -o ./bin/rund ./cmd/rund && sudo ./bin/rund serve ''${@}'
    ''
    )

    (
      pkgs.writeShellScriptBin "cli" ''
        set -e
        ${pkgs.go}/bin/go run ./cmd/runc ''${@}
    ''
    )
  ];
}
