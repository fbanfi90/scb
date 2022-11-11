#!/bin/sh

echo "thisisasecretkey" > key

../bin/scb_image ecb 1 1 key sec/matterhorn.png
../bin/scb_image enc 1 3 key sec/matterhorn.png
../bin/scb_image enc 2 3 key sec/matterhorn.png

if diff -q sec/{,ref/}matterhorn.ecb.png; then echo "OK"; else echo "FAIL"; fi
if diff -q sec/{,ref/}matterhorn.enc_1_3.png; then echo "OK"; else echo "FAIL"; fi
if diff -q sec/{,ref/}matterhorn.enc_2_3.png; then echo "OK"; else echo "FAIL"; fi

rm sec/matterhorn.ecb.png
rm sec/matterhorn.enc_1_3.png
rm sec/matterhorn.enc_2_3.png

../bin/scb_image enc 2 1 key cor/tux.png
../bin/scb_image enc 2 2 key cor/tux.png
../bin/scb_image enc 2 3 key cor/tux.png

../bin/scb_image dec 2 1 key cor/tux.enc_2_1.png
../bin/scb_image dec 2 2 key cor/tux.enc_2_2.png
../bin/scb_image dec 2 3 key cor/tux.enc_2_3.png

if diff -q cor/{,ref/}tux.enc_2_1.dec.png; then echo "OK"; else echo "FAIL"; fi
if diff -q cor/{,ref/}tux.enc_2_2.dec.png; then echo "OK"; else echo "FAIL"; fi
if diff -q cor/{,ref/}tux.enc_2_3.dec.png; then echo "OK"; else echo "FAIL"; fi

rm cor/tux.enc_2_1.png
rm cor/tux.enc_2_2.png
rm cor/tux.enc_2_3.png

rm cor/tux.enc_2_1.dec.png
rm cor/tux.enc_2_2.dec.png
rm cor/tux.enc_2_3.dec.png

rm key