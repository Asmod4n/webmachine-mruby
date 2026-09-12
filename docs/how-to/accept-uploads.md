# Accept uploads

This how-to is for a developer whose resource needs to read a request
body, or put an upload on disk. At the end, you know the size limits,
how to read a body as an IO, and how to save one to a directory named
for its own content.

## The size limit

`conf.max_body` is the largest body an application accepts, in bytes;
1 MiB is the default. A `Content-Length` above the limit gets 413
before one byte of the body is read. A resource may set a limit of its
own with `def self.max_body`, which wins over `conf.max_body` when
both are set.

```ruby
def main
  Webmachine::Application.new do |app|
    app.conf.max_body = 8 * 1024 * 1024
    app.add_route [:*], Upload
  end
end
```

## Naming the callback that reads a body

Waiting for a body is a stop, and every stop this server makes is
declared. `reads_body` names the callback a body may reach:
`process_post`, `create_path`, or a handler `content_types_accepted`
points at. A resource that defines one of those and never names it
with `reads_body` is refused, by name, at start.

```ruby
class Upload < Webmachine::Resource
  reads_body :process_post

  def self.allowed_methods
    %w[GET POST]
  end

  def process_post
    response.body = request.body.read.bytesize.to_s
    true
  end

  def self.to_html
    'upload'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.max_body = 8 * 1024 * 1024
    app.add_route [:*], Upload
  end
end
```

## request.body as an IO

`request.body` answers `nil` when no body arrived, or an IO otherwise:
`read`, `gets`, `getc`, `each`, `pos`, `seek`, `rewind`, `size` and
`eof?` all work on it. A body under 256 KiB stays in memory as a
`StringIO`. From 256 KiB up, it spills to a file - `TMPDIR`, then
`/tmp`, unless `conf.spill_dir` names a directory of its own. Naming
one on the disk the uploads live on turns the save below into a link
instead of a copy.

## Saving a body by content

A callback that saves an upload declares that too, with `save: true`
beside its name:

```ruby
class Saved < Webmachine::Resource
  reads_body :take, save: true

  def self.allowed_methods
    %w[GET PUT]
  end

  def self.content_types_accepted
    [['application/octet-stream', :take]]
  end

  def take
    request.body.save('/var/uploads', request.headers['x-name'] || 'blob.bin') do |dir, err|
      dir
    end
    true
  end
end
```

`body.save(dir, name)` puts the upload under
`<dir>/<first two hex of its sha256>/<full sha256 hex>/<name>`. The
block gets `(dir, err)`, exactly one of the two set; whatever it
answers, if truthy, becomes the response body with `to_s`. Two uploads
of the same bytes get the same directory, so the second upload of
identical content writes nothing and costs nothing: the digest is the
name, and `mkdir` is the atomic claim on it. Without a block,
`body.save` returns the directory directly, or raises
`Webmachine::Error` on a failure; a failed save always raises, block or
not, because it is this server's own fault and not a 4xx the resource
should have to spell.

## Next

- [work-off-the-loop.md](work-off-the-loop.md)
- [../reference/request-and-response.md](../reference/request-and-response.md)
- [../reference/configuration.md](../reference/configuration.md)
