@echo off

cmd /a /c echo thisisasecretkey> key

..\bin\scb_image.exe ecb 1 1 key sec\matterhorn.png
..\bin\scb_image.exe enc 1 3 key sec\matterhorn.png
..\bin\scb_image.exe enc 2 3 key sec\matterhorn.png

fc /b sec\matterhorn.ecb.png sec\ref\matterhorn.ecb.png > nul
if errorlevel 1 (echo FAIL) else (echo OK)
fc /b sec\matterhorn.enc_1_3.png sec\ref\matterhorn.enc_1_3.png > nul
if errorlevel 1 (echo FAIL) else (echo OK)
fc /b sec\matterhorn.enc_2_3.png sec\ref\matterhorn.enc_2_3.png > nul
if errorlevel 1 (echo FAIL) else (echo OK)

del sec\matterhorn.ecb.png
del sec\matterhorn.enc_1_3.png
del sec\matterhorn.enc_2_3.png

..\bin\scb_image.exe enc 2 1 key cor\tux.png
..\bin\scb_image.exe enc 2 2 key cor\tux.png
..\bin\scb_image.exe enc 2 3 key cor\tux.png

..\bin\scb_image.exe dec 2 1 key cor\tux.enc_2_1.png
..\bin\scb_image.exe dec 2 2 key cor\tux.enc_2_2.png
..\bin\scb_image.exe dec 2 3 key cor\tux.enc_2_3.png

fc /b cor\tux.enc_2_1.dec.png cor\ref\tux.enc_2_1.dec.png > nul
if errorlevel 1 (echo FAIL) else (echo OK)
fc /b cor\tux.enc_2_2.dec.png cor\ref\tux.enc_2_2.dec.png > nul
if errorlevel 1 (echo FAIL) else (echo OK)
fc /b cor\tux.enc_2_3.dec.png cor\ref\tux.enc_2_3.dec.png > nul
if errorlevel 1 (echo FAIL) else (echo OK)

del cor\tux.enc_2_1.png
del cor\tux.enc_2_2.png
del cor\tux.enc_2_3.png

del cor\tux.enc_2_1.dec.png
del cor\tux.enc_2_2.dec.png
del cor\tux.enc_2_3.dec.png

del key