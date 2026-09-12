# Command line reference

This page is for an operator who runs the shipped programs or the
build's rake tasks. At the end, you know every flag of every program,
every rake task and what it does, and what each build config is for.

## webmachine-server

```
usage: webmachine-server [OPTIONS]

  Every option is --key=value. There are two ways to serve:
  an application (--app), or standalone (--standalone), which
  serves files and enters no VM. One of the two, or no start.

FILES
  --mime-types=FILE        this media-type database, not the machine's

LOG
  --log=FILE               the access log
  --log-privacy=MODE       none | anon | full                       (anon)
  --error-log=FILE         what a callback raised; mrbc -g for line numbers
  --log-max-bytes=N        ceiling on the access log, 0 = none    (500 MB)

TUNE
  --zero-copy-threshold=N  lend a body this big instead of copying (128 KiB)
  --file-map-threshold=N   map a file this big instead of reading  (256 KiB)

OTHER
  --config=FILE.toml       these choices from a file; flags beat it.
                           Without it: ./webmachine.toml, then
                           /usr/local/etc/webmachine/, then /etc/webmachine/
  --write-config[=PATH]    write that file with the defaults in it, and stop
  --pidfile=PATH           write this pid, remove it on the way out

AN APPLICATION
  --app=FILE.mrb           the application, as bytecode - required
  --error-assets=FILE.zip  what an error answer may hand over
                           The listener, the pack and the docroot are the
                           application's own: conf.port, conf.unix_path,
                           conf.url, conf.assets, conf.docroot. One process
                           serves any number of applications.

STANDALONE - files only, and the folded graph answers them
  --standalone             no app, no route, no VM entry per request
  --unix=PATH              answer on a unix socket
  --port=N                 answer on a TCP port
  --assets=FILE.zip        answered first, from its mapping
  --docroot=DIR            answered next, from disk; needs one of the two
                           GET and HEAD; a directory takes its index.html
```

With no arguments and nothing to serve, it prints:

```
webmachine: nothing to serve - name an application with --app=FILE.mrb (or app = in the config), or serve files with --standalone and --assets/--docroot
```

`--app=FILE.mrb` is required to serve an application. The file must be
mruby bytecode, not source. A `.rb` path is refused:
`<path> is Ruby source, not bytecode - this server loads bytecode
only. Compile it first: mrbc -g -o <base>.mrb <path>`. Compiling
without `-g` still loads, but the server warns once at start that a
raise in that file will name no file and no line.

`--unix`, `--port`, `--assets` and `--docroot` are standalone-only
flags, and each is refused alongside `--app`: naming both means the
listener, pack and docroot are named twice, once by the app's own conf
and once here.

## mrbc

```
Usage: ./mrbc [switches] programfile...
  switches:
  -c           check syntax only
  -o<outfile>  place the output into <outfile>; required for multi-files
  -v           print version number, then turn on verbose mode
  -g           produce debugging information
  -B<symbol>   binary <symbol> output in C language format
  -S           dump C struct (requires -B)
  -s           define <symbol> as static variable
  --remove-lv  remove local variables
  --no-ext-ops prohibit using OP_EXTs
  --no-optimize disable peephole optimization
  --verbose    run at verbose mode
  --version    print the version
  --copyright  print the copyright
```

`mrbc -g -o app.mrb app.rb` compiles an app file to the bytecode
`webmachine-server --app` reads, with line numbers kept for a raise to
name. `mrbc -c FILE` checks syntax only, without writing an output
file.

## webmachine-logd

```
usage: webmachine-logd access FILE MAXBYTES [full|anon|none]  (records on fd 0)
       webmachine-logd error  FILE MAXBYTES
```

`webmachine-logd` reads log records from file descriptor 0 and writes
them to `FILE`, capped at `MAXBYTES`. The `access` form also takes a
privacy mode: `full` keeps the address, `anon` drops the host part,
`none` writes no address.

## webmachine-passwd

```
usage: webmachine-passwd COMMAND [OPTIONS]

  create FILE            make the database
  add    FILE DB USER    add a user, refusing one that exists
  set    FILE DB USER    add or replace a user
  del    FILE DB USER    remove a user
  list   FILE DB         the users, when they were made and last changed
  calibrate              what each cost setting takes here

DB names a sub-database inside FILE - one set of users. The
server is pointed at the same pair.

OPTIONS
  --maxdbs N       how many sub-databases FILE may ever hold (16)
  --mapsize MiB    the ceiling FILE may grow to (64)
  --time MS        the time one login may cost; picks the cost (0 = default)
  --workers N      how many hashes run at once, for the rate this prints (8)
  --sort HOW       list order: user, created or changed (user)
  --names          list bare names, for a script to read
```

`FILE` is one LMDB file that can hold several `DB` sub-databases, each
one set of users. `create`, `add`, `set`, `del` and `list` all take
`FILE`; `add`, `set`, `del` and `list` also take `DB`, and `add`, `set`
and `del` also take `USER`.

## rake tasks

| Task | Description |
| --- | --- |
| `rake compile` | build |
| `rake test` | build and run every test |
| `rake san_test[which]` | build and run every test under a sanitizer: `rake san_test[asan]` or `[tsan]` |
| `rake san_smoke[which]` | a sanitizer build starts and answers: `rake san_smoke[asan]` or `[tsan]` |
| `rake deps_update` | pull mruby and every gem this tree tracks by branch (a clone is made once and never updated) |
| `rake ship_test` | the bintests against the ship binary, not the debug one |
| `rake ship_smoke` | the ship binary starts and answers - what the suite (debug) never checks |
| `rake error_assets` | rebuild `share/error-assets.zip`: the cats, one per status |
| `rake pack[dir,out,compact]` | pack a directory for `--assets`: `rake pack[DIR,OUT.zip,compact]` |
| `rake site` | build the example site: `examples/site.zip` and `examples/site.mrb` |
| `rake install[prefix]` | install the ship build: `rake install[PREFIX]`, PREFIX is `/usr/local` |
| `rake config_example` | regenerate `webmachine.toml.example` from the server itself |
| `rake clean` | remove build output (keeps the mruby checkout) |

The default task, `rake` with no task name, runs `compile`.

Only the debug config is built while developing:

```
MRUBY_CONFIG=build_config_debug.rb rake compile
MRUBY_CONFIG=build_config_debug.rb rake test
```

The release build is checked separately: `rake ship_smoke` builds the
host config and checks that the binary starts and answers 200; `rake
test` never touches it, because the suite is the debug build's.

### rake pack[DIR,OUT.zip,compact]

Packs every file under `DIR` into `OUT.zip`, the zip an `--assets` or
`conf.assets` server answers from. Files whose name, or any path
segment, starts with a dot are skipped. An HTML document is stored
under the plain name it is called by; every other file gets a second,
hashed name for cache-busting, besides the plain one. The optional third
argument, the literal word `compact`, writes the zip without entries no
name points to any more.

### rake install[PREFIX]

Installs the ship build under `PREFIX`, by the Filesystem Hierarchy
Standard, and refuses when the ship build is missing (run `rake
ship_smoke` first):

- `PREFIX/bin`: `webmachine-server`, `webmachine-logd`,
  `webmachine-passwd`, and `mrbc`.
- `PREFIX/share/webmachine-mruby`: `error-assets.zip`.
- `PREFIX/etc/webmachine`: `webmachine.toml`, written by
  `--write-config` and kept if one is already there.

## Build configs

| File | What it is for |
| --- | --- |
| `build_config_debug.rb` | The development build. Used for `rake compile` and `rake test`. |
| `build_config_host.rb` | The ship build: the two binaries an operator installs, and nothing else. |
| `build_config_example.rb` | The host build's flags, plus the C++ resource example, kept separate so the example is never part of what ships. |
| `build_config_asan.rb` | The debug build plus AddressSanitizer and UndefinedBehaviorSanitizer, for a memory bug that stalls a connection instead of crashing it. |
| `build_config_tsan.rb` | The debug build plus ThreadSanitizer, for a race in the compute pool. |
| `build_config_pgo.rb` | A profile-guided-optimization build. |
| `build_config_fuzz.rb` | The shipped server, unchanged in behavior, compiled so memory errors speak, fed on the socket like a real attacker would. |
| `build_config_libfuzzer.rb` | The same server sources, with libFuzzer's entry point instead of the CLI's, for fuzzing calls directly. |

## Next

- [../tutorial.md](../tutorial.md)
- [configuration.md](configuration.md)
- [request-and-response.md](request-and-response.md)
