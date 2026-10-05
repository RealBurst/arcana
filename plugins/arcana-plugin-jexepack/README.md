# arcana-plugin-jexepack

Arcana plugin for **JexePack** executables (Duckware): Java programs packed into a Windows `.exe`.
It shows and extracts what the executable really contains, to check it before running it.

| | |
|---|---|
| Versions | JexePack 5.x, 7.x and 8.x (formats worked out from the 5.5, 7.3b, 8.2d and 8.3a launchers) |
| Extracted | the jar files and DLLs of the program, the bootstrap class (`Boot.class` or `jexepackboot.class`), the extra files of 7.x/8.x programs (DLLs, sources, embedded installers), the settings (`jexepack-settings.txt`: main class, Java options, jar names) |
| Checks | check value of every record (as the launcher does) |
| Capabilities | extract, list, identify (`arcana i`) |

## Usage

```
arcana i program.exe
arcana l program.exe
arcana x program.exe -o out
arcana l out/java.jar             (then look inside the jar)
```

## License

Apache-2.0. Format worked out from the behaviour of the JexePack launcher; no Duckware code is included.
