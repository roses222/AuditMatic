from services.workbook_service import read_software_list_universal_rows, VersionRuleResolver
rows = read_software_list_universal_rows(r"C:\Users\cornetct\Downloads\N65236-GEOINT-AUD-0377-1.00 GEOINT CGW-L-N 2.0.2.2 AUD BUILD 1.xlsx")
print("Total rows:", len(rows))
for r in rows:
    name = r.get("SOFTWARE COMPONENT", "")
    instr = r.get("VERSION LOCATIONS", "")
    rule, _ = VersionRuleResolver.detect_rule(instr)
    if rule == "manual_steps":
        print(f"=== {name} ===")
        print(instr)
        print()
