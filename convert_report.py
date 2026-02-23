import json
import csv

# Input JSON file
with open("report.json", "r") as f:
    data = json.load(f)

# Output CSV file
with open("report.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["id", "severity", "title", "evidence", "remediation"])
    writer.writeheader()
    writer.writerows(data)

print("✅ Conversion complete! Check report.csv")
