# RE2Net native co-op prototype

Early development components for an opt-in Resident Evil 2 Remake co-op mod.
This repository contains the original C++ door transaction core, native adapter,
bounded local-channel transport, source test fixtures and the pinned REFramework
SDK headers needed to compile them. It is not affiliated with or endorsed by Capcom.

## Development status

This is a **source prototype, not a playable co-op release**. The R1525 baseline
compiled locally with Microsoft C++ tools (15 build/link steps, no warnings).
The current native test programs and DLL have not been run: local application
control blocked unsigned programs. No test results, runtime ABI compatibility,
animated-door passage or campaign success follow from compilation. This project
does not disable Windows security or ask users to disable it.

The authenticated Python companion, direct native/Lua ownership handoff, improved
local flow guard, complete normal key progression and full campaign integration
are separate ongoing work, not supplied by this source snapshot. Do not install
this DLL in a game or describe it as ready for human co-op testing.

The intended product remains a full co-op campaign with either player able to
progress, shared story keys in both inventories and independent ordinary loot,
including weapons. That target is not implemented or validated by this snapshot.

## Build without running native code

Use Windows x64, CMake 3.20 or newer and Visual Studio C++ build tools supporting
C++20. From this repository root:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The supplied workflow compiles only. It does not run CTest, test executables,
the plugin DLL, the game or external gameplay automation. No game executable,
assets, proprietary runtime or game installation is required to compile.
REFramework SDK headers are vendored unchanged at revision
`c4b1314820d20255febf7834903e8cedb669b49c`, under the upstream MIT license.
The Windows SDK/compiler and static Microsoft C++ runtime are build dependencies;
their treatment under any free-signing program remains subject to that program.

## Source and distribution boundary

Only the listed original native sources and unchanged MIT SDK headers are here.
No Capcom/Valve binaries, game assets, extracted scenarios, decompiled game output,
HUNK/pad code, REFramework loader DLL, saves, game/session logs or private account
configuration are included. Source pins are in SOURCE_MANIFEST.json.
The game and REFramework runtime would be separate dependencies of a future mod;
SignPath's assessment of that proprietary game-host relationship is pending.

## License

Original project code is released under the MIT license in LICENSE.
Third-party SDK files retain their separate upstream MIT notice in
third_party/reframework/LICENSE. This grant covers the supplied project source;
it does not grant rights to Capcom, Valve or other third-party game material.

## Code signing policy

See CODE_SIGNING_POLICY.md. No SignPath sponsorship or certificate has been granted.
No signing service should be represented as endorsing the project at this stage.

## Privacy

See PRIVACY.md, including the persistent local diagnostic journal and its per-file
limits. This snapshot is not enabled or installed. A future complete mod
and companion will require their own reviewed data-flow and privacy statements.
