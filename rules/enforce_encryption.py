def get_metadata():
    return {
        "id": "enforce_encryption",
        "severity": "High",
        "category": "Security",
        "description": "Ensures that encryption is enabled for Azure storage accounts."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("enforce_encryption", True):
        return []

    # Quick filter: only scan if the resource is relevant
    if "azurerm_storage_account" not in code.lower():
        return []

    lines = code.split("\n")
    encryption_found = False

    for i, line in enumerate(lines):
        if "enable_blob_encryption" in line.lower():
            encryption_found = True
            break

    if not encryption_found:
        results.append({
            "rule": "enforce_encryption",
            "severity": "High",
            "category": "Security",
            "file": file_name,
            "line": 1,  # Could refine this later to where `azurerm_storage_account` appears
            "message": "🔒 Storage account missing encryption config",
            "suggestion": "Set `enable_blob_encryption = true` to enforce data protection."
        })

    return results