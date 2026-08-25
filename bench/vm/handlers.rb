
def wm_noop; end

def wm_handle(req)
  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
end
