import re

pattern = r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
counts = {}
usernames = {}

with open("samples/auth.log") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            username = match.group(1)
            ip = match.group(2)
            counts[ip] = counts.get(ip, 0) + 1
            usernames.setdefault(ip, set()).add(username)

for ip, total in counts.items():
    if total >= 3:
        print(ip, total, sorted(usernames[ip]))