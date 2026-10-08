"""A compile database for a Visual Studio C project, written from its
.vcxproj: one clang-cl entry per compiled source, with the configuration's
preprocessor definitions and include directories.

A Win32 corpus has no Linux build to run under bear, but its project file
declares exactly what its build compiles and with which flags. That is the
declared configuration (docs/adr/0018), so the database is read from it
rather than from a build. The entries name clang-cl, so aurora-lint reads
them with cl's rules (matching #include names ignoring case, as cl does).

  python3 -m bench.vcxproj_db PROJECT.vcxproj 'Release|Win32' [TARGET]

prints the database on stdout; TARGET is clang-cl's --target, default
i686-pc-windows-msvc (the Win32 platform).
"""

import json
import posixpath
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}


def _condition_matches(element, config: str) -> bool:
    cond = element.get("Condition")
    return cond is None or f"=='{config}'" in cond.replace(" ", "")


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(";") if v.strip() and not v.strip().startswith("%(")]


def database(project: Path, config: str, target: str = "i686-pc-windows-msvc") -> list[dict]:
    root = ET.parse(project).getroot()
    proj_dir = project.parent.resolve()
    defines, includes = [], []
    unicode = False
    for group in root.findall("m:PropertyGroup", NS):
        if _condition_matches(group, config):
            cs = group.find("m:CharacterSet", NS)
            if cs is not None and cs.text == "Unicode":
                unicode = True
    for group in root.findall("m:ItemDefinitionGroup", NS):
        if not _condition_matches(group, config):
            continue
        cl = group.find("m:ClCompile", NS)
        if cl is None:
            continue
        d = cl.find("m:PreprocessorDefinitions", NS)
        if d is not None and d.text:
            defines += _split(d.text)
        i = cl.find("m:AdditionalIncludeDirectories", NS)
        if i is not None and i.text:
            includes += _split(i.text)
    if unicode:
        # What the IDE adds for a Unicode character set.
        defines += ["UNICODE", "_UNICODE"]
    flags = [f"--target={target}"] + [f"-D{d}" for d in defines]
    flags += ["-I" + str((proj_dir / posixpath.normpath(i.replace("\\", "/"))).resolve())
              for i in includes]
    flags += ["-I" + str(proj_dir)]
    entries = []
    for group in root.findall("m:ItemGroup", NS):
        for item in group.findall("m:ClCompile", NS):
            src = item.get("Include").replace("\\", "/")
            if not src.endswith(".c"):
                continue
            path = str((proj_dir / src).resolve())
            entries.append({"directory": str(proj_dir), "file": path,
                            "arguments": ["clang-cl", *flags, "-c", path]})
    return entries


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in (2, 3):
        print(__doc__)
        return 2
    print(json.dumps(database(Path(args[0]), args[1], *args[2:]), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
