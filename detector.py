with open("samples/auth.log") as file:
    for line in file:
        if "Failed password" in line:
            print(line.strip())