/* nix-build -E 'with import <nixpkgs> { }; callPackage ./junkie.nix { }' */
{ stdenv, fetchurl, pkgconfig, libpcap, guile, openssl }:

stdenv.mkDerivation {
  name = "junkie-2.8.0";
  meta = {
    license = stdenv.lib.licenses.agpl3Plus;
    description = "Deep packet inspection swiss-army knife";
    longDescription = ''
      Junkie is a network sniffer like Tcpdump or Wireshark, but designed to
      be easy to program and extend.

      It comes with several command line tools to demonstrate this:
      - a packet dumper;
      - a nettop tool;
      - a tool listing TLS certificates...
    '';
    homepage = "https://github.com/rixed/junkie";
  };
  src = fetchurl {
    url = https://github.com/rixed/junkie/archive/v2.8.0.tar.gz;
    sha256 = "c9b57bd6e06d4f90e6a88b775f33fa00f66313ba0f663df70198eddf1d4be298";
  };
  buildInputs = [ pkgconfig libpcap guile openssl ];
  configureFlags = [
    "GUILELIBDIR=\${out}/share/guile/site"
    "GUILECACHEDIR=\${out}/lib/guile/ccache"
  ];
}
