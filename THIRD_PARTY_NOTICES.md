# Third-party notices

This repository is a proof of concept. It contains code and data derived from
the projects below, each under its own licence. Nothing here changes or
supersedes those licences.

## avast/apkparser - LGPL-3.0

<https://github.com/avast/apkparser>

The AXML / `resources.arsc` parsing code under `pkg/manifest` derives from
apkparser (`apkparser.go`, `stringtable.go`, `resources.go`, `binxml.go`,
`zipreader.go`, `common.go`, `encoder.go`, and the attribute table in
`attributes.go`). Maintainer: confirm this file list against the original
import and correct it if a file is missing or does not belong.

LGPL-3.0 is a copyleft licence: these files, and modified versions of them,
stay under LGPL-3.0. The licence text is at
<https://www.gnu.org/licenses/lgpl-3.0.html>. Redistributing a binary built
from this repository means the recipient must be able to relink those parts -
which is satisfied here because the full corresponding source is in this
repository.

If you would rather not carry an LGPL dependency, the parser is the part to
replace.

## Kaitai Struct runtime - MIT

<https://github.com/kaitai-io/kaitai_struct_go_runtime> (Go module dependency,
not vendored). MIT licence.

`pkg/dex/kaitai_dex.go` and `pkg/dex/vlq_base128_le.go` are output of the
Kaitai Struct compiler. The `.ksy` source they were generated from is **not**
in this repository - see CONTRIBUTING.md if you need to regenerate them.

## Android platform resource ids

`pkg/manifest/attributes.go` maps resource ids to attribute names, taken from
the platform's `android.R.attr` table (AOSP, Apache-2.0). The ids are
interface facts, not creative content.

## Frida Gadget - wxWindows Library Licence

<https://frida.re>, <https://github.com/frida/frida>

The gadget binaries in `frida_gadget/` are upstream release artifacts of Frida
17.18.0 for Android, redistributed unmodified. Frida is licensed under the
wxWindows Library Licence, an LGPL-2.1-based licence with an exception for
static linking; its text ships with Frida at
<https://github.com/frida/frida-core/blob/main/COPYING>.

Those binaries are **not** covered by this repository's own licence. If you
prefer not to redistribute someone else's binaries, run
`tools/fetch-frida-gadget.sh`, which downloads and hash-checks them from the
upstream release instead.
