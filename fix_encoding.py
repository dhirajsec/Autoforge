import os

log_path = "reports/refresh_log.json"

# Read file using UTF-16 encoding
with open(log_path, "r", encoding="utf-16") as f:
    raw = f.read()

# Write file back using UTF-8
with open(log_path, "w", encoding="utf-8") as f:
    f.write(raw)

print("✅ Re-encoded refresh_log.json to UTF-8")