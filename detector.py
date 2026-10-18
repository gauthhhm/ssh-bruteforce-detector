import re

pattern = r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"

with open("samples/auth.log") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            username = match.group(1)
            ip = match.group(2)
            print(username, ip)