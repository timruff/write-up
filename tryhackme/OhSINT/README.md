# OhSINT #

## Introduction ## 
***
Ce write-up nous apprend à rechercher des informations.

***
**What is this users avatar of?**

Dans le fichier télécharger on trouve un fichier WindowsXP.jpg

Regardons les métas données du fichier avec exiftool.jpg
 
 ```bash
 tim@kali:~/Bureau/tryhackme/ohsint$ exiftool WindowsXP.jpg 
ExifTool Version Number         : 12.16
File Name                       : WindowsXP.jpg
Directory                       : .
File Size                       : 229 KiB
File Modification Date/Time     : 2021:04:06 11:00:55+02:00
File Access Date/Time           : 2021:04:06 11:03:25+02:00
File Inode Change Date/Time     : 2021:04:06 11:03:25+02:00
File Permissions                : rwxrwx---
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 11.27
GPS Latitude                    : 54 deg 17' 41.27" N
GPS Longitude                   : 2 deg 15' 1.33" W
Copyright                       : OWoodflint
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1080
Megapixels                      : 2.1
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Position                    : 54 deg 17' 41.27" N, 2 deg 15' 1.33" W
```

Dans la section Copyright on remarque le mot : OWoodflint

Faisons une recherche sur moteur de recherche avec l'occurrence  OWoodflint

![Alt text](ressources/moteur-de-recherche.jpg)