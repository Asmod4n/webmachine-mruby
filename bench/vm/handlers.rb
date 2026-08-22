# The copy floor's Ruby half, and the two bench resources. Loaded as
# BYTECODE (#100): the server carries no compiler, so neither does the
# benchmark that measures it - bench/vm.sh compiles this with the mrbc
# the build produced.

def wm_noop; end

def wm_handle(req)
  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
end
