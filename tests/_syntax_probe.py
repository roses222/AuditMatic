from pathlib import Path
import ast
import traceback

target = Path(r"c:/Users/15026/Desktop/Work/Repos/AUDTOOLTEST/sbl_audit_gui_v_2000.py")
report = Path(r"c:/Users/15026/Desktop/Work/Repos/AUDTOOLTEST/_syntax_report.txt")

lines = []
lines.append(f"TARGET={target}")

try:
    text = target.read_text(encoding="utf-8")
    lines.append(f"LENGTH={len(text)}")
    ast.parse(text, filename=str(target))
    lines.append("PARSE=OK")
except SyntaxError as e:
    lines.append("PARSE=SYNTAX_ERROR")
    lines.append(f"LINE={e.lineno}")
    lines.append(f"OFFSET={e.offset}")
    lines.append(f"MSG={e.msg}")
    lines.append(f"TEXT={repr(e.text)}")
    if e.lineno and 1 <= e.lineno <= len(text.splitlines()):
        src_lines = text.splitlines()
        start = max(1, e.lineno - 2)
        end = min(len(src_lines), e.lineno + 2)
        for idx in range(start, end + 1):
            lines.append(f"{idx}: {src_lines[idx-1]}")
except Exception as exc:
    lines.append(f"PARSE=OTHER_ERROR:{exc}")
    lines.append(traceback.format_exc())

report.write_text("\n".join(lines), encoding="utf-8")
print(report)
