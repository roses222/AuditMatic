import json
import re
import winreg
from difflib import SequenceMatcher
from pathlib import Path

MASTER_JSON = Path(r"c:/Users/15026/Desktop/Work/Repos/AUDTOOLTEST/JSON/master_software_list.json")


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def simplify_generic(display_name: str) -> str:
    name = display_name.strip()

    if name.lower().startswith("microsoft visual c++"):
        return "Microsoft Visual C++"

    # Remove architecture and parenthetical suffixes.
    name = re.sub(r"\s*\((x86|x64|32-bit|64-bit)\)\s*", " ", name, flags=re.IGNORECASE)
    name = re.sub(r"\s*\([^)]*\)\s*", " ", name)

    # Remove obvious version-like tails.
    name = re.sub(r"\b\d{4}(?:-\d{4})?\b", "", name)
    name = re.sub(r"\b\d+(?:\.\d+)+\b", "", name)

    # Remove common packaging words.
    name = re.sub(r"\bredistributable\b", "", name, flags=re.IGNORECASE)

    name = re.sub(r"\s+", " ", name).strip(" -")
    return name or display_name


def installed_program_names() -> list[str]:
    results: list[str] = []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, root in roots:
        try:
            with winreg.OpenKey(hive, root) as base:
                for idx in range(winreg.QueryInfoKey(base)[0]):
                    try:
                        sub = winreg.EnumKey(base, idx)
                        with winreg.OpenKey(base, sub) as sk:
                            display_name = str(winreg.QueryValueEx(sk, "DisplayName")[0]).strip()
                            if display_name:
                                results.append(display_name)
                    except Exception:
                        continue
        except Exception:
            continue

    # Stable unique list preserving first appearance.
    seen = set()
    deduped = []
    for item in results:
        key = normalize(item)
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def best_registry_match(component_name: str, registry_items: list[str]) -> str:
    component_n = normalize(component_name)

    # Company standard preference for VC++ family.
    if "microsoft visual c++" in component_n:
        vc_matches = [n for n in registry_items if normalize(n).startswith("microsoft visual c++")]
        if vc_matches:
            # Choose latest-looking entry by lexical order as a simple deterministic heuristic.
            return sorted(vc_matches)[-1]

    scored = []
    for candidate in registry_items:
        cand_n = normalize(candidate)

        contains_bonus = 0.0
        if component_n in cand_n or cand_n in component_n:
            contains_bonus = 0.25

        ratio = SequenceMatcher(None, component_n, cand_n).ratio()
        score = ratio + contains_bonus
        scored.append((score, candidate))

    scored.sort(key=lambda x: x[0], reverse=True)
    best_score, best_name = scored[0]

    # Require a minimum confidence to avoid bad mappings.
    if best_score < 0.45:
        return ""
    return best_name


def main() -> None:
    payload = json.loads(MASTER_JSON.read_text(encoding="utf-8"))
    models = payload.get("SBL_models", {})

    registry_items = installed_program_names()
    updated = 0

    for _, model_entry in models.items():
        if not isinstance(model_entry, dict):
            continue

        bucket = model_entry.get("software_components", {})
        if not isinstance(bucket, dict):
            continue

        for component, entry in bucket.items():
            if not isinstance(entry, dict):
                continue

            ver_source = normalize(str(entry.get("verification_source", "")))
            if ver_source != "programs_and_features":
                # Keep generic naming for non-programs-and-features as-is when populated.
                if not entry.get("generic_name"):
                    entry["generic_name"] = component
                continue

            best = best_registry_match(component, registry_items)
            if best:
                old_registry = str(entry.get("registry_name", ""))
                old_generic = str(entry.get("generic_name", ""))

                entry["registry_name"] = best
                entry["generic_name"] = simplify_generic(best)

                if old_registry != entry["registry_name"] or old_generic != entry["generic_name"]:
                    updated += 1

    MASTER_JSON.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"UPDATED_COMPONENTS={updated}")


if __name__ == "__main__":
    main()
