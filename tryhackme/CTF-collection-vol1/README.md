# CTF collection Vol.1 #

## Task 1 Author note  ##

## Task 2 What does the base said? ##

**Feed me the flag!**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo -n "VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==" | base64 -d
THM{ju57_d3c0d3_7h3_b453}
```

C'est base64.
La réponse est : THM{ju57_d3c0d3_7h3_b453} 

## Task 3 Meta meta  ##
**I'm hungry, I need the flag.**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ exiftool Findme.jpg 
ExifTool Version Number         : 12.16
File Name                       : Findme.jpg
Directory                       : .
File Size                       : 34 KiB
File Modification Date/Time     : 2021:07:20 22:21:02+02:00
File Access Date/Time           : 2021:07:20 22:23:01+02:00
File Inode Change Date/Time     : 2021:07:20 22:23:01+02:00
File Permissions                : rwxrwx---
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 96
Y Resolution                    : 96
Exif Byte Order                 : Big-endian (Motorola, MM)
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
Flashpix Version                : 0100
Owner Name                      : THM{3x1f_0r_3x17}
Comment                         : CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 60.
Image Width                     : 800
Image Height                    : 480
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 800x480
Megapixels                      : 0.384
```
On la réponse dans Owner name.  
La réponse est : THM{3x1f_0r_3x17} 

## Task 4 Mon, are we going to be okay?  ##
**It is sad. Feed me the flag.**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ steghide --extract -sf Extinction.jpg 
Entrez la passphrase: 
�criture des donn�es extraites dans "Final_message.txt".
tim@kali:~/Bureau/tryhackme/write-up$ cat Final_message.txt 
It going to be over soon. Sleep my child.

THM{500n3r_0r_l473r_17_15_0ur_7urn}
```

Il suffire d'extraire les données avec steghide.  
La réponse est : THM{500n3r_0r_l473r_17_15_0ur_7urn}  