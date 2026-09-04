"""Safe Case: Resource explicitly closed on every execution path."""


def read_conditional_content(flag: bool):
    f = open("content.txt", "r")
    if flag:
        data = f.read()
        f.close()
        return data.strip()
    else:
        line = f.readline()
        f.close()
        return line.strip()
