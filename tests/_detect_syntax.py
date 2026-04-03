from pathlib import Path

p = Path(r"c:/Users/15026/Desktop/Work/Repos/AUDTOOLTEST/sbl_audit_gui_v_2000.py")
s = p.read_text(encoding="utf-8")

try:
    compile(s, str(p), "exec")
    print("OK")
except SyntaxError as e:
    print("LINE", e.lineno)
    print("OFFSET", e.offset)
    print("TEXT", repr(e.text))
    print("MSG", e.msg)
