---
layout: post
title: VeeBeeEee
date: 23 Nov 2023
tags: huntress2023 malware vbe sed
---

![Challenge Text for VeeBeeEee](/docs/assets/images/Huntress2023/VeeBeeEee/Challenge.png)

# What I did

The challenge name itself pretty much hints at the file being a .vbe file. John Hammond himself has a vbe-decoder [here](https://github.com/JohnHammond/vbe-decoder){:target="_blank"}.

Using this script to decode the file we will see code that is *slightly-obfuscated*.
```
python3 vbe-decoder.py ../Documents/Huntress2023/veebeeeee > veebeeeee.vbs
```
![Decoded vbs script](/docs/assets/images/Huntress2023/VeeBeeEee/decoded.png)

Use sed to remove the '&' and we can see that the code invoke-webrequest towards a pastebin.com URL.
```
sed 's/&//g' veebeeeee.vbs > veebeeeee.tmp
```
![Removed '&'](/docs/assets/images/Huntress2023/VeeBeeEee/decoded.png)


Navigate to the pastebin.com link and we will see the flag. 

# Alternative for decoding vbe

CyberChef has a recipe that allows us to decode vbe files. All we have to do is to dump the file into CyberChef and select 'Microsoft Script Decoder'.

![CyberChef Microsoft Script Decoder](/docs/assets/images/Huntress2023/VeeBeeEee/CyberChef.png)


