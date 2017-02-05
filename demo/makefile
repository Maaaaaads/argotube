
client:
	gcc -Wall -o client client.c ../kernel/string/ascs2std.c ../kernel/crypt/opendes.c ../kernel/encoder/code2x.c ../kernel/string/hexstok.c ../kernel/header/headers.c ../library/hsocket.c -lcrypto
server:
	gcc -Wall -o server server.c ../kernel/string/ascs2std.c ../kernel/crypt/opendes.c ../kernel/encoder/code2x.c ../kernel/string/hexstok.c ../kernel/header/headers.c ../library/hsocket.c -lcrypto
cclient:	
	rm -f client
cserver:
	rm -f server
clean:
	rm -f client
	rm -f server
