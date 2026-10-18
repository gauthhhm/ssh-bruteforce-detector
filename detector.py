import re

pattern = r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
counts = {}

with open("samples/auth.log") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            ip = match.group(2)
            counts[ip] = counts.get(ip, 0) + 1

for ip, total in counts.items():
    if total >= 3:
        print(ip, total)