# wiretap-auto

Zero-configuration capture for [wiretap](https://github.com/ssx/wiretap).
Records outbound HTTP calls made by **any** code in the process — including
your vendor directory, which you cannot edit.

```bash
composer require ssx/wiretap-auto
pecl install opentelemetry     # see below
```

That is the entire install. No service provider, no bootstrap line, no SPI.
Composer's autoloader registers the hooks.

## What it captures that middleware cannot

```php
// Untouched vendor code, three directories deep. Captured.
$ch = curl_init('https://api.example.com/v1/orders');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$body = curl_exec($ch);

// A Guzzle client with no middleware attached at all. Captured.
$response = (new GuzzleHttp\Client())->get('https://api.example.com/v1');
```

Guzzle's default handler is `CurlMultiHandler`, so hooking curl catches Guzzle
for free. There is one writer at the lowest layer rather than two recorders
that then have to be de-duplicated.

## How it works

`ext-opentelemetry` exposes PHP's `zend_observer` API to userland. This package
uses it to observe the whole curl handle lifecycle:

| Hook | Why it is needed |
| --- | --- |
| `curl_init` | register the handle, capture a URL passed to the constructor |
| `curl_setopt`, `curl_setopt_array` | curl options are **write-only** — there is no `curl_getopt()`, so the only way to know a handle's URL or POSTFIELDS is to watch every call go past |
| `curl_copy_handle` | a copied handle inherits the options, so the shadow state must be copied too |
| `curl_reset` | returns the handle to defaults |
| `curl_exec` | pre: run the blocklist gate and install capture options. post: the return value **is** the response body |
| `curl_close` | release the shadow state |

### Two things it deliberately does not do

**It does not force `CURLOPT_RETURNTRANSFER`.** Without it the application is
streaming to stdout or a file handle, and switching it changes where the
response goes. The body is recorded as `omitted: not-returned` instead. A
missing body is a bug report; a corrupted download is an incident.

**It does not set `CURLINFO_HEADER_OUT` when the application set
`CURLOPT_VERBOSE`.** The two occupy the same libcurl debug slot and setting one
silently blanks the other, with no warning and no error
([bug 65348](https://bugs.php.net/bug.php?id=65348)). If you asked for verbose
output, you keep it, and wiretap falls back to the headers you configured.

An application's `CURLOPT_HEADERFUNCTION` is chained, never replaced.

## Requirements

- **PHP 8.2+.** The extension runs on 8.0+, but observation of *internal*
  functions — which `curl_exec` is — arrived in PHP 8.2. On 8.1 the same API
  sees only userland functions, so raw curl would be invisible.
- **`ext-opentelemetry`.** Install with `pecl install opentelemetry`, then add
  `extension=opentelemetry.so` to the php.ini of the SAPI that actually runs
  your application, and restart its workers.

`opentelemetry.allow_stack_extension` is **not** required. It is only needed to
*add arguments* in a pre-hook, which this package never does.

Without the extension the package is inert rather than broken: it registers
nothing and records nothing. CI covers that case explicitly.

## Nothing is captured until you say so

```bash
WIRETAP_ENABLED=true
WIRETAP_PATH=/var/log/wiretap        # default: system temp
WIRETAP_BODY_LIMIT=65536
WIRETAP_SAMPLE_BP=10000              # basis points; 10000 = keep everything
WIRETAP_BLOCK=api.internal.test,*.acquirer.test
WIRETAP_DISABLE_AUTO=true            # skip hook registration entirely
```

A package that started recording personal data the moment it was installed
would be indefensible, so capture is off unless `WIRETAP_ENABLED` is truthy.

The `payment-gateways` and `cloud-metadata` blocklist presets are on by
default. Cloud metadata endpoints hand out short-lived IAM credentials;
capturing one puts a live token in your log.

## Wiring in your own recorder

```php
use Ssx\Wiretap\Auto\Wiretap;

Wiretap::setRecorder($myConfiguredRecorder);
```

Safe to call after autoload. The hooks resolve the recorder per call rather
than capturing it at registration, precisely so a framework booting later can
swap in one that is properly wired.

## Diagnostics

```php
print_r(Ssx\Wiretap\Auto\Wiretap::diagnostics());
```

Reports the extension state, whether hooks registered, live handle count,
blocklist pattern counts by source, and whether the blocklist has failed
closed. This exists because "why is nothing being recorded" otherwise costs an
afternoon.

## ⚠️ Do not leave it running

Wiretap records complete request and response bodies. See the
[main README](https://github.com/ssx/wiretap) — it is not PCI-DSS compliant and
not GDPR compliant on its own.

## Licence

MIT.
