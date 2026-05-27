# Icons

`icon.png` is a 32×32 solid dark-indigo placeholder generated for D.1.1 so the
`tauri::generate_context!()` macro can compile. Real branding is a deferred
slice (post-D.1.1 — see `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md` §13).

To regenerate the placeholder (Python stdlib only — no external deps):

```bash
python3 -c "
import struct, zlib
W, H = 32, 32
RGBA = bytes((30, 30, 90, 255))
def chunk(typ, data):
    crc = zlib.crc32(typ + data) & 0xffffffff
    return struct.pack('>I', len(data)) + typ + data + struct.pack('>I', crc)
sig = b'\\x89PNG\\r\\n\\x1a\\n'
ihdr = struct.pack('>IIBBBBB', W, H, 8, 6, 0, 0, 0)
raw = b''.join(b'\\x00' + RGBA * W for _ in range(H))
png = sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')
open('icon.png', 'wb').write(png)
"
```

To replace with real branding, use the Tauri CLI to generate the per-platform
icon variants Tauri expects for `tauri build`:

```bash
pnpm tauri icon path/to/source-1024x1024.png
```

This produces `icon.icns` (macOS), `icon.ico` (Windows), and a set of PNG sizes
under `icons/`. Update `tauri.conf.json`'s `bundle.icon` array to reference
them, then drop this placeholder.
