#!/bin/sh
# Does a browser get h2 over TLS out of this server?
#
# Six steps, easiest first, each answering a different question - a
# browser is last because it is the only one that will not say what went
# wrong. Everything lands in a temporary directory that is named at the
# end and not deleted, so a failing step can be looked at.
#
#   tools/tls-first-light.sh [port]
#
# Needs: a debug build (MRUBY_CONFIG=build_config_debug.rb rake compile),
# openssl and curl on the path, and the tls module in the kernel.
set -eu

port=${1:-8443}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin=$root/mruby/build/debug/bin/webmachine-server
mrbc=$root/mruby/build/host/mrbc/bin/mrbc
work=$(mktemp -d)
fails=0

say() { printf '\n== %s\n' "$1"; }
ok()  { printf '   %-56s %s\n' "$2" "$1"; [ "$1" = ok ] || fails=$((fails + 1)); }

[ -x "$bin" ]  || { echo "no debug binary at $bin - rake compile first"; exit 1; }
[ -x "$mrbc" ] || { echo "no mrbc at $mrbc - rake compile first"; exit 1; }

# The tls module is NOT checked here on purpose. setsockopt(TCP_ULP,
# "tls") makes the kernel autoload it, and the server does exactly that
# at startup - so a check here would refuse a machine the server can
# serve on. The kernel drops the module again when nothing is using it,
# which is why asking lsmod first was the wrong question.

say "1. a certificate a browser can be told to trust"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 30 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
[ -s "$work/cert.pem" ] && ok ok "a self-signed P-256 certificate for localhost" \
                        || ok FAILED "openssl req"

cat > "$work/app.rb" <<APP
class Hello < Webmachine::Resource
  def self.to_html
    '<html><body><h1>h2 over tls</h1></body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    app.configure do |conf|
      conf.url = 'https://localhost:$port'
      conf.certificate = '$work/cert.pem'
      conf.private_key = '$work/key.pem'
    end
    app.routes { |route| route.add [:*], Hello }
  end
end
APP
"$mrbc" -o "$work/app.mrb" "$work/app.rb" >/dev/null

say "2. does the server come up on a TLS listener?"
"$bin" --app="$work/app.mrb" >"$work/out.log" 2>"$work/err.log" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT INT TERM
i=0
while [ $i -lt 100 ]; do
  if ! kill -0 $server 2>/dev/null; then
    ok FAILED "the server exited during startup"
    sed 's/^/   | /' "$work/err.log"
    echo "   files in $work"
    exit 1
  fi
  (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
  i=$((i + 1))
  sleep 0.1
done
grep -q ', tls' "$work/err.log" && ok ok "it says the listener is tls" \
                                || ok FAILED "the startup line does not mention tls"
sed -n 's/^webmachine: \(listener 0 offers.*\)$/   \1/p' "$work/err.log"

say "3. does the handshake finish, and on which suite?"
# A request rather than Q, and -ign_eof, so this connection does NOT hang
# up the moment the handshake finishes: a peer leaving right then is a
# race the server can only lose, and it was this script provoking it and
# then reporting it as the server's fault.
hs=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
     | openssl s_client -connect "127.0.0.1:$port" -CAfile "$work/cert.pem" \
         -alpn h2,http/1.1 -servername localhost -ign_eof 2>&1 || true)
echo "$hs" | grep -q 'Verification: OK' \
  && ok ok "the certificate verifies" || ok FAILED "verification"
suite=$(echo "$hs" | sed -n 's/^.*Cipher is \(TLS_[A-Z0-9_]*\).*$/\1/p' | head -1)
[ -n "$suite" ] && ok ok "negotiated $suite" || ok FAILED "no suite was negotiated"
echo "$hs" | grep -q 'ALPN protocol: h2' \
  && ok ok "ALPN settled on h2" || ok FAILED "ALPN did not settle on h2"

say "4. does ONE plain request come back, in HTTP/1.1?"
# Before h2, because h2 failing tells you nothing about which half broke:
# this is the smallest thing the kernel's record layer has to carry.
raw=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
      | openssl s_client -connect "127.0.0.1:$port" -CAfile "$work/cert.pem" \
          -alpn http/1.1 -servername localhost -quiet -ign_eof 2>/dev/null || true)
echo "$raw" | grep -q '^HTTP/1.1 200' \
  && ok ok "HTTP/1.1 over TLS answers 200" \
  || ok FAILED "no HTTP/1.1 answer"
echo "$raw" | grep -q 'h2 over tls' \
  && ok ok "and the body is the resource's" || ok FAILED "no body"

say "5. and over h2, which is what a browser will ask for"
body=$(curl -sS --http2 --cacert "$work/cert.pem" --resolve "localhost:$port:127.0.0.1" \
         -w '\n%{http_version} %{http_code}' "https://localhost:$port/" 2>&1 || true)
echo "$body" | grep -q '^2 200$' \
  && ok ok "HTTP/2, status 200" || ok FAILED "not h2/200: $(echo "$body" | tail -1)"

say "6. and four of them on one connection, where a browser lives"
# One -o per URL: curl applies a single one to the first URL only, and the
# bodies would otherwise land in the answer being compared.
many=$(curl -sS --http2 --cacert "$work/cert.pem" --resolve "localhost:$port:127.0.0.1" \
       -w '%{http_code} ' \
       -o /dev/null "https://localhost:$port/"  -o /dev/null "https://localhost:$port/a" \
       -o /dev/null "https://localhost:$port/b" -o /dev/null "https://localhost:$port/c" 2>&1 || true)
[ "$many" = "200 200 200 200 " ] \
  && ok ok "four requests, one connection" || ok FAILED "got: $many"

# The one question a failure above cannot answer by itself: were those
# bytes wrong, or were they the wrong PROTOCOL? An h2 client that is
# answered in HTTP/1.1 reports a framing error and shows nothing.
if [ $fails -ne 0 ]; then
  say "what the server actually sent, after ALPN chose h2"
  printf 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' \
    | openssl s_client -connect "127.0.0.1:$port" -CAfile "$work/cert.pem" \
        -alpn h2 -servername localhost -quiet -ign_eof 2>/dev/null \
    | head -c 96 | od -c | head -8 | sed 's/^/   | /'
  echo "   (bytes starting 'H T T P / 1 . 1' mean the preface never reached"
  echo "    the parser; noise means the record layer or the buffer layout)"
fi

printf '\n'
if [ $fails -eq 0 ]; then
  echo "all ok - point a browser at https://localhost:$port/ and accept the"
  echo "self-signed certificate; its network panel should say h2."
  echo "the server is still running as pid $server, files in $work"
  trap - EXIT INT TERM
else
  echo "$fails step(s) failed. The server's own log:"
  sed 's/^/   | /' "$work/err.log"
  echo "files in $work"
fi
exit $fails
