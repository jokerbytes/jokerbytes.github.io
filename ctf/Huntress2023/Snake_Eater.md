---
layout: post 
title: Snake Eater
date: 23 Nov 2023
tags: #huntress2023 #malware #pyinstaller
---

![Challenge Text for Snake Eater](/docs/assets/images/Huntress2023/SnakeEater/SnakeEater_Challenge.png)

# What I did - but did not work

My attempt at static analysis eventually ended when I hit a wall in the form of PyArmor. Below I document the steps for my own reference when dealing with PyInstaller in future.

## Static Analysis

Firing up Detect-It-Easy we can see PyInstaller in place.

![Snake Eater Detect It Easy Results](/docs/assets/images/Huntress2023/SnakeEater/SnakeEater_DetectItEasy.png)

I then extracted the code with [PyInstxtractor](https://github.com/extremecoders-re/pyinstxtractor){:target="_blank"}.
```
python3 pyinstxtractor.py ~/Documents/Huntress2023/snake_eater.exe
```
![Snake Eater PyInstaller Extractor](/docs/assets/images/Huntress2023/SnakeEater/SnakeEater_PyInstallerExtractor.png)

There is some error regarding the Python version. At this point in time I am not aware of a tool that can decompile Python 3.11 without any error. I inspected the pyc and saw the presence of PyArmor so I switched to dynamic analysis on the file.

![Snake Eater PyArmor](/docs/assets/images/Huntress2023/SnakeEater/SnakeEater_PyArmor.png)

## Dynamic Analysis
I loaded the file in a Windows VM and started ProcMon and add a filter for the snake_eater process.
![ProcMon filter for Snake Eater](/docs/assets/images/Huntress2023/SnakeEater/ProcMon_Filter.png)

Save the output in ProcMon into a csv file and run findstr - luckily it can be found immediately. 
```
findstr flag{ SnakeEater.CSV
```
![findstr results with the flag](/docs/assets/images/Huntress2023/SnakeEater/FindStr_flag.png)

# The recommended way

The recommended way by the challenge author huskyhacks is documented in this [Youtube video](https://www.youtube.com/watch?v=Zcp4Qc7B260){:target="_blank"}.

We will need to fire up ProcMon, and add a filter to look for snake_eater.exe. This will give us a lot of events. Examining the network activities we see nothing, but there are plenty of file-based activities we have to examine. We can exclude some of the operations (QueryNameInformationFile, ReadFile, CloseFile, etc) to reduce the number of events for analysis.

![ProcMon Exclude Operation](/docs/assets/images/Huntress2023/SnakeEater/ProcMon_ExcludeCloseFile.png)

We can scroll down the list (although there are still a lot of events) and see that snake_eater.exe is creating a file with the flag.

![ProcMon Results](/docs/assets/images/Huntress2023/SnakeEater/ProcMon_Results.png)


