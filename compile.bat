@echo off

if not exist "obj" md obj
if not exist "bin" md bin

cl /Ox /Iinclude /c /Fo:obj/hashmap.obj src/hashmap.c
cl /Ox /Iinclude /IC:\openssl-3\x64\include /c /Fo:obj/scb.obj src/scb.c
cl /Ox /Iinclude /IC:\openssl-3\x64\include /c /Fo:obj/scb_file.obj src/scb_file.c
cl /Ox /Iinclude /IC:\openssl-3\x64\include /c /Fo:obj/scb_image.obj src/scb_image.c

link C:\openssl-3\x64\lib\libssl.lib C:\openssl-3\x64\lib\libcrypto.lib /OUT:bin/scb_file.exe obj/scb_file.obj obj/scb.obj obj/hashmap.obj
link C:\openssl-3\x64\lib\libssl.lib C:\openssl-3\x64\lib\libcrypto.lib /OUT:bin/scb_image.exe obj/scb_image.obj obj/scb.obj obj/hashmap.obj