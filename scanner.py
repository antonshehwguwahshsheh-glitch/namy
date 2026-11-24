import os
import hashlib
import sys

SUSPICIOUS_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".js", ".jse", ".wsf", ".ps1", ".jar"
}

DOUBLE_EXT = (
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe",
    ".png.exe", ".txt.exe", ".zip.exe", ".rar.exe"
)


def resource_path(name):
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_signatures(sig_file):
    sigs = {}
    if not os.path.exists(sig_file):
        return sigs
    with open(sig_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 1)
            if len(parts) == 2:
                sigs[parts[0].lower()] = parts[1].strip()
    return sigs


def scan_folder(root, sig_file=None, progress_cb=None):
    if sig_file is None:
        sig_file = resource_path("signatures.txt")

    sigs = load_signatures(sig_file)
    findings = []

    files = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            files.append(os.path.join(dirpath, name))

    total = len(files)

    for i, path in enumerate(files, 1):
        if progress_cb:
            progress_cb(i, total)

        if not os.path.isfile(path):
            continue

        name = os.path.basename(path).lower()
        reasons = []

        ext = os.path.splitext(name)[1]
        if ext in SUSPICIOUS_EXT:
            reasons.append(f"подозрительное расширение: {ext}")

        for de in DOUBLE_EXT:
            if name.endswith(de):
                reasons.append(f"двойное расширение: {de}")
                break

        file_hash = ""
        try:
            file_hash = sha256(path)
            if file_hash in sigs:
                reasons.append(f"сигнатура: {sigs[file_hash]}")
        except OSError as e:
            reasons.append(f"ошибка чтения: {e}")

        if reasons:
            findings.append({
                "path": path,
                "size": os.path.getsize(path) if os.path.exists(path) else 0,
                "sha256": file_hash,
                "reasons": "; ".join(reasons),
            })

    return findings
