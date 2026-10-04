# arcana-plugin-jexepack

Arcana plugin for **JexePack** executables (Duckware): Java programs packed into a Windows `.exe`.
It shows and extracts what the executable really contains, to check it before running it.

| | |
|---|---|
| Versions | JexePack 5.x (format worked out from the 5.5 launcher); other versions as long as they keep the same records |
| Extracted | the jar files and DLLs of the program, the bootstrap class (`Boot.class`), the settings (`jexepack-settings.txt`: main class, Java options, jar names) |
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
