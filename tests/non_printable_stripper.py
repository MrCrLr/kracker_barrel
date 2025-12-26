with open("cleaned_rockyou.txt", "r", encoding="utf-8", errors="ignore") as infile, open("final_rockyou.txt", "w", encoding="utf-8") as outfile:
    for line in infile:
        if line.isprintable():
            outfile.write(line)