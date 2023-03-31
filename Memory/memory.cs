using System;
using System.IO;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using System.Threading.Tasks;
using System.ComponentModel;
using static Memory.Imps;
using System.Collections.Concurrent;
using System.Threading;

namespace Memory
{
    /// <summary>
    /// Memory.dll class. Full documentation at https://github.com/erfg12/memory.dll/wiki
    /// </summary>
    public partial class Mem
    {
        public Proc mProc = new Proc();

        public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
        {
            UIntPtr retVal;

            // TODO: Need to change this to only check once.
            if (mProc.Is64Bit || IntPtr.Size == 8)
            {
                // 64 bit
                MEMORY_BASIC_INFORMATION64 tmp64 = new MEMORY_BASIC_INFORMATION64();
                retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64, new UIntPtr((uint)Marshal.SizeOf(tmp64)));

                lpBuffer.BaseAddress = tmp64.BaseAddress;
                lpBuffer.AllocationBase = tmp64.AllocationBase;
                lpBuffer.AllocationProtect = tmp64.AllocationProtect;
                lpBuffer.RegionSize = (long)tmp64.RegionSize;
                lpBuffer.State = tmp64.State;
                lpBuffer.Protect = tmp64.Protect;
                lpBuffer.Type = tmp64.Type;

                return retVal;
            }
            MEMORY_BASIC_INFORMATION32 tmp32 = new MEMORY_BASIC_INFORMATION32();

            retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

            lpBuffer.BaseAddress = tmp32.BaseAddress;
            lpBuffer.AllocationBase = tmp32.AllocationBase;
            lpBuffer.AllocationProtect = tmp32.AllocationProtect;
            lpBuffer.RegionSize = tmp32.RegionSize;
            lpBuffer.State = tmp32.State;
            lpBuffer.Protect = tmp32.Protect;
            lpBuffer.Type = tmp32.Type;

            return retVal;
        }

        /// <summary>
        /// Open the PC game process with all security and access rights.
        /// </summary>
        /// <param name="pid">Use process name or process ID here.</param>
        /// <returns>Process opened successfully or failed.</returns>
        /// <param name="FailReason">Show reason open process fails</param>
        public bool OpenProcess(int pid, out string FailReason)
        {
            /*if (!IsAdmin())
            {
                Debug.WriteLine("WARNING: This program may not be running with raised privileges! Visit https://github.com/erfg12/memory.dll/wiki/Administrative-Privileges");
            }*/

            if (pid <= 0)
            {
                FailReason = "OpenProcess given proc ID 0.";
                Debug.WriteLine("ERROR: OpenProcess given proc ID 0.");
                return false;
            }


            if (mProc.Process != null && mProc.Process.Id == pid)
            {
                FailReason = "mProc.Process is null";
                return true;
            }

            try
            {
                mProc.Process = Process.GetProcessById(pid);

                if (mProc.Process != null && !mProc.Process.Responding)
                {
                    Debug.WriteLine("ERROR: OpenProcess: Process is not responding or null.");
                    FailReason = "Process is not responding or null.";
                    return false;
                }

                mProc.Handle = Imps.OpenProcess(0x1F0FFF, true, pid);

                try {
                    Process.EnterDebugMode(); 
                } catch (Win32Exception) {
                    //Debug.WriteLine("WARNING: You are not running with raised privileges! Visit https://github.com/erfg12/memory.dll/wiki/Administrative-Privileges"); 
                }

                if (mProc.Handle == IntPtr.Zero)
                {
                    var eCode = Marshal.GetLastWin32Error();
                    Debug.WriteLine("ERROR: OpenProcess has failed opening a handle to the target process (GetLastWin32ErrorCode: " + eCode + ")");
                    Process.LeaveDebugMode();
                    mProc = null;
                    FailReason = "failed opening a handle to the target process(GetLastWin32ErrorCode: " + eCode + ")";
                    return false;
                }

                // Lets set the process to 64bit or not here (cuts down on api calls)
                mProc.Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(mProc.Handle, out bool retVal) && !retVal);

                mProc.MainModule = mProc.Process.MainModule;

                //GetModules();

                Debug.WriteLine("Process #" + mProc.Process + " is now open.");
                FailReason = "";
                return true;
            }
            catch (Exception ex) {
                Debug.WriteLine("ERROR: OpenProcess has crashed. " + ex);
                FailReason = "OpenProcess has crashed. " + ex;
                return false;
            }
        }


        /// <summary>
        /// Open the PC game process with all security and access rights.
        /// </summary>
        /// <param name="proc">Use process name or process ID here.</param>
        /// <param name="FailReason">Show reason open process fails</param>
        /// <returns></returns>
        public bool OpenProcess(string proc, out string FailReason)
        {
            return OpenProcess(GetProcIdFromName(proc), out FailReason);
        }

        /// <summary>
        /// Open the PC game process with all security and access rights.
        /// </summary>
        /// <param name="proc">Use process name or process ID here.</param>
        /// <returns></returns>
        public bool OpenProcess(string proc)
        {
            return OpenProcess(GetProcIdFromName(proc), out string FailReason);
        }

        /// <summary>
        /// Open the PC game process with all security and access rights.
        /// </summary>
        /// <param name="pid">Use process name or process ID here.</param>
        /// <returns></returns>
        public bool OpenProcess(int pid)
        {
            return OpenProcess(pid, out string FailReason);
        }

        /*public bool IsAdmin()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            } 
            catch
            {
                Debug.WriteLine("ERROR: Could not determin if program is running as admin. Is the NuGet package \"System.Security.Principal.Windows\" missing?");
                return false;
            }
        }*/

        /// <summary>
        /// Builds the process modules dictionary (names with addresses). Use mProc.Process.Modules instead.
        /// </summary>
        /*public ConcurrentDictionary<string, IntPtr> GetModules()
        {
            if (mProc.Process == null)
            {
                Debug.WriteLine("mProc.Process is null so GetModules failed.");
                return null;
            }

            if (mProc.Is64Bit && IntPtr.Size != 8)
            {
                Debug.WriteLine("WARNING: Game is x64, but your Trainer is x86! You will be missing some modules, change your Trainer's Solution Platform.");
            }
            else if (!mProc.Is64Bit && IntPtr.Size == 8)
            {
                Debug.WriteLine("WARNING: Game is x86, but your Trainer is x64! You will be missing some modules, change your Trainer's Solution Platform.");
            }

            if (mProc.Process.Modules == null)
            {
                Debug.WriteLine("mProc.Process.Modules is null so GetModules failed.");
                return null;
            }

            if (mProc.Modules != null)
                mProc.Modules.Clear();
            else
                mProc.Modules = new ConcurrentDictionary<string, IntPtr>();

            foreach (ProcessModule Module in mProc.Process.Modules)
            {
                if (Module.ModuleName == null || Module.BaseAddress == null)
                    continue;

                if (!string.IsNullOrEmpty(Module.ModuleName) && !mProc.Modules.ContainsKey(Module.ModuleName))
                    mProc.Modules.TryAdd(Module.ModuleName, Module.BaseAddress);
            }

            Debug.WriteLine("Found " + mProc.Modules.Count() + " process modules.");
            return mProc.Modules;
        }*/

        public void SetFocus()
        {
            //int style = GetWindowLong(procs.MainWindowHandle, -16);
            //if ((style & 0x20000000) == 0x20000000) //minimized
            //    SendMessage(procs.Handle, 0x0112, (IntPtr)0xF120, IntPtr.Zero);
            SetForegroundWindow(mProc.Process.MainWindowHandle);
        }

        /// <summary>
        /// Get the process ID number by process name.
        /// </summary>
        /// <param name="name">Example: "eqgame". Use task manager to find the name. Do not include .exe</param>
        /// <returns></returns>
        public int GetProcIdFromName(string name) //new 1.0.2 function
        {
            Process[] processlist = Process.GetProcesses();

            if (name.ToLower().Contains(".exe"))
                name = name.Replace(".exe", "");
            if (name.ToLower().Contains(".bin")) // test
                name = name.Replace(".bin", "");

            foreach (System.Diagnostics.Process theprocess in processlist)
            {
                if (theprocess.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase)) //find (name).exe in the process list (use task manager to find the name)
                    return theprocess.Id;
            }

            return 0; //if we fail to find it
        }



        /// <summary>
        /// Get code. If just the ini file name is given with no path, it will assume the file is next to the executable.
        /// </summary>
        /// <param name="name">label for address or code</param>
        /// <param name="iniFile">path and name of ini file</param>
        /// <returns></returns>
        public string LoadCode(string name, string iniFile)
        {
            StringBuilder returnCode = new StringBuilder(1024);
            uint read_ini_result;

            if (!String.IsNullOrEmpty(iniFile))
            {
                if (File.Exists(iniFile))
                {
                    read_ini_result = GetPrivateProfileString("codes", name, "", returnCode, (uint)returnCode.Capacity, iniFile);
                    //Debug.WriteLine("read_ini_result=" + read_ini_result); number of characters returned
                }
                else
                    Debug.WriteLine("ERROR: ini file \"" + iniFile + "\" not found!");
            }
            else
                returnCode.Append(name);

            return returnCode.ToString();
        }

        private int LoadIntCode(string name, string path)
        {
            try
            {
                int intValue = Convert.ToInt32(LoadCode(name, path), 16);
                if (intValue >= 0)
                    return intValue;
                else
                    return 0;
            } catch
            {
                Debug.WriteLine("ERROR: LoadIntCode function crashed!");
                return 0;
            }
        }

        /// <summary>
        /// Make a named pipe (if not already made) and call to a remote function.
        /// </summary>
        /// <param name="func">remote function to call</param>
        /// <param name="name">name of the thread</param>
        public void ThreadStartClient(string func, string name)
        {
            //ManualResetEvent SyncClientServer = (ManualResetEvent)obj;
            using (NamedPipeClientStream pipeStream = new NamedPipeClientStream(name))
            {
                if (!pipeStream.IsConnected)
                    pipeStream.Connect();

                //MessageBox.Show("[Client] Pipe connection established");
                using (StreamWriter sw = new StreamWriter(pipeStream))
                {
                    if (!sw.AutoFlush)
                        sw.AutoFlush = true;
                    sw.WriteLine(func);
                }
            }
        }        

        #region protection

        public bool ChangeProtection(string code, MemoryProtection newProtection, out MemoryProtection oldProtection, string file = "")
        {
	        UIntPtr theCode = GetCode(code, file);
	        if (theCode == UIntPtr.Zero 
	            || mProc.Handle == IntPtr.Zero)
	        {
		        oldProtection = default;
		        return false;
	        }

	        return VirtualProtectEx(mProc.Handle, theCode, (IntPtr)(mProc.Is64Bit ? 8 : 4), newProtection, out oldProtection);
        }
        #endregion

        /// <summary>
        /// Convert code from string to real address. If path is not blank, will pull from ini file.
        /// </summary>
        /// <param name="name">label in ini file or code</param>
        /// <param name="path">path to ini file (OPTIONAL)</param>
        /// <param name="size">size of address (default is 8)</param>
        /// <returns></returns>
        public UIntPtr GetCode(string name, string path = "", int size = 8)
        {
            //return if Process = null
            if (mProc.Process == null) return UIntPtr.Zero;

            //if Process = 64Bit
            if (mProc.Is64Bit) size = 16;

            //if string Empty
            if (name == "") return UIntPtr.Zero;

            // remove spaces 0x
            name = name.Replace(" ", "").Replace("0x", "");
            //if Simple Code
            if (!name.Contains("+") && !name.Contains(",") && !name.Contains("."))
            {
                if (size == 8)//if 32bit Code
                    return (UIntPtr)Convert.ToUInt32(name, 16);
                else          //if 64bit Code
                    return (UIntPtr)Convert.ToUInt64(name, 16);
            }
            //Get BaseAddress
            IntPtr Mod = IntPtr.Zero;
            if ((name.StartsWith("base")) || name.StartsWith("main"))
                Mod = mProc.MainModule.BaseAddress;
            else
            {
                if (name.Contains("+"))
                    Mod = GetModuleAddressByName(name.Split('+')[0]);
                else if (!name.Contains("+") && name.Contains("."))
                    Mod = GetModuleAddressByName(name);
            }

            //GetOffset
            UIntPtr RetVal = UIntPtr.Zero;
            if (name.Contains(","))
            {
                List<UInt32> offsets = new List<UInt32>();
                foreach (string con in name.Split(',', '+'))
                {
                    if (!con.Contains("."))
                        offsets.Add(Convert.ToUInt32(con.Replace("-", ","), 16));
                }
                byte[] memoryAddress = new byte[size];
                ReadProcessMemory(mProc.Handle, (UIntPtr)(Mod.ToInt64() + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                if (size == 8)
                {
                    for (int i = 1; i < offsets.Count; i++)
                    {
                        uint num = BitConverter.ToUInt32(memoryAddress, 0);
                        RetVal = (UIntPtr)(num + offsets[i]);
                        ReadProcessMemory(mProc.Handle, RetVal, memoryAddress, (UIntPtr)size, IntPtr.Zero);                
                    }
                }
                else
                {
                    for (int i = 1; i < offsets.Count; i++)
                    {
                        long num1 = BitConverter.ToInt64(memoryAddress, 0);
                        RetVal = (UIntPtr)(num1 + offsets[i]);
                        ReadProcessMemory(mProc.Handle, RetVal, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    }
                }
            }
            else
            {
                //if Simple Code2
                if (name.Contains("+") && !name.Contains(",")) //+
                {
                    if (name.Split('+')[1] == "")
                        RetVal = (UIntPtr)Mod.ToInt64();
                    else
                        RetVal = (UIntPtr)(Mod.ToInt64() + Convert.ToUInt32(name.Split('+')[1], 16));
                }
                else
                {
                    RetVal = (UIntPtr)Mod.ToInt64();
                }
            }

            return RetVal;
        }

        /// <summary>
        /// Retrieve mProc.Process module baseaddress by name
        /// </summary>
        /// <param name="name">name of module</param>
        /// <returns></returns>
        public IntPtr GetModuleAddressByName (string name)
        {
            return mProc.Process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase)).BaseAddress;
        }

        /// <summary>
        /// Close the process when finished.
        /// </summary>
        public void CloseProcess()
        {
            if (mProc.Handle == null)
                return;

            CloseHandle(mProc.Handle);
            mProc = null;
        }

        /// <summary>
        /// Inject a DLL file.
        /// </summary>
        /// <param name="strDllName">path and name of DLL file. Ex: "C:\MyTrainer\inject.dll" or "inject.dll" if the DLL file is in the same directory as the trainer.</param>
        public bool InjectDll(String strDllName)
        {
            IntPtr bytesout;

            if (mProc.Process == null)
            { // check if process is open first
                Debug.WriteLine("Inject failed due to mProc.Process being null. Is the process not open?");
                return false;
            }

            foreach (ProcessModule pm in mProc.Process.Modules)
            {
                if (pm.ModuleName.StartsWith("inject", StringComparison.InvariantCultureIgnoreCase))
                    return false;
            }

            if (!mProc.Process.Responding)
                return false;

            int lenWrite = strDllName.Length + 1;
            UIntPtr allocMem = VirtualAllocEx(mProc.Handle, (UIntPtr)null, (uint)lenWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            WriteProcessMemory(mProc.Handle, allocMem, strDllName, (UIntPtr)lenWrite, out bytesout);
            UIntPtr GameProc = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (GameProc == null)
                return false;

            IntPtr hThread = CreateRemoteThread(mProc.Handle, (IntPtr)null, 0, GameProc, allocMem, 0, out bytesout);

            int Result = WaitForSingleObject(hThread, 10 * 1000);
            if (Result == 0x00000080L || Result == 0x00000102L)
            {
                if (hThread != null)
                    CloseHandle(hThread);
                return false;
            }
            VirtualFreeEx(mProc.Handle, allocMem, (UIntPtr)0, 0x8000);

            if (hThread != null)
                CloseHandle(hThread);

            return true;
        }

#if WINXP
#else
        /// <summary>
        /// Creates a code cave to write custom opcodes in target process
        /// </summary>
        /// <param name="code">Address to create the trampoline</param>
        /// <param name="newBytes">The opcodes to write in the code cave</param>
        /// <param name="replaceCount">The number of bytes being replaced</param>
        /// <param name="size">size of the allocated region</param>
        /// <param name="file">ini file to look in</param>
        /// <remarks>Please ensure that you use the proper replaceCount
        /// if you replace halfway in an instruction you may cause bad things</remarks>
        /// <returns>UIntPtr to created code cave for use for later deallocation</returns>
        public UIntPtr CreateCodeCave(string code, byte[] newBytes, int replaceCount, int size = 0x1000, string file = "")
        {
            if (replaceCount < 5)
                return UIntPtr.Zero; // returning UIntPtr.Zero instead of throwing an exception
                                     // to better match existing code

            UIntPtr theCode;
            theCode = GetCode(code, file);
            UIntPtr address = theCode;

            // if x64 we need to try to allocate near the address so we dont run into the +-2GB limit of the 0xE9 jmp

            UIntPtr caveAddress = UIntPtr.Zero;
            UIntPtr prefered = address;

            for(var i = 0; i < 10 && caveAddress == UIntPtr.Zero; i++)
            {
                caveAddress = VirtualAllocEx(mProc.Handle, FindFreeBlockForRegion(prefered, (uint)size), (uint)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (caveAddress == UIntPtr.Zero)
                    prefered = UIntPtr.Add(prefered, 0x10000);
            }

            // Failed to allocate memory around the address we wanted let windows handle it and hope for the best?
            if (caveAddress == UIntPtr.Zero)
                caveAddress = VirtualAllocEx(mProc.Handle, UIntPtr.Zero, (uint)size, MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);

            int nopsNeeded = replaceCount > 5 ? replaceCount - 5 : 0;

            // (to - from - 5)
            int offset = (int)((long)caveAddress - (long)address - 5);

            byte[] jmpBytes = new byte[5 + nopsNeeded];
            jmpBytes[0] = 0xE9;
            BitConverter.GetBytes(offset).CopyTo(jmpBytes, 1);

            for(var i = 5; i < jmpBytes.Length; i++)
            {
                jmpBytes[i] = 0x90;
            }

            byte[] caveBytes = new byte[5 + newBytes.Length];
            offset = (int)(((long)address + jmpBytes.Length) - ((long)caveAddress + newBytes.Length) - 5);

            newBytes.CopyTo(caveBytes, 0);
            caveBytes[newBytes.Length] = 0xE9;
            BitConverter.GetBytes(offset).CopyTo(caveBytes, newBytes.Length + 1);

            WriteBytes(caveAddress, caveBytes);
            WriteBytes(address, jmpBytes);

            return caveAddress;
        }
        
        private UIntPtr FindFreeBlockForRegion(UIntPtr baseAddress, uint size)
        {
            UIntPtr minAddress = UIntPtr.Subtract(baseAddress, 0x70000000);
            UIntPtr maxAddress = UIntPtr.Add(baseAddress, 0x70000000);

            UIntPtr ret = UIntPtr.Zero;
            UIntPtr tmpAddress = UIntPtr.Zero;

            GetSystemInfo(out SYSTEM_INFO si);

            if (mProc.Is64Bit)
            {
                if ((long)minAddress > (long)si.maximumApplicationAddress ||
                    (long)minAddress < (long)si.minimumApplicationAddress)
                    minAddress = si.minimumApplicationAddress;

                if ((long)maxAddress < (long)si.minimumApplicationAddress ||
                    (long)maxAddress > (long)si.maximumApplicationAddress)
                    maxAddress = si.maximumApplicationAddress;
            }
            else
            {
                minAddress = si.minimumApplicationAddress;
                maxAddress = si.maximumApplicationAddress;
            }

            MEMORY_BASIC_INFORMATION mbi;

            UIntPtr current = minAddress;
            UIntPtr previous = current;

            while (VirtualQueryEx(mProc.Handle, current, out mbi).ToUInt64() != 0)
            {
               if ((long)mbi.BaseAddress > (long)maxAddress)
                    return UIntPtr.Zero;  // No memory found, let windows handle

                if (mbi.State == MEM_FREE && mbi.RegionSize > size)
                {
                    if ((long)mbi.BaseAddress % si.allocationGranularity > 0)
                    {
                        // The whole size can not be used
                        tmpAddress = mbi.BaseAddress;
                        int offset = (int)(si.allocationGranularity -
                                           ((long)tmpAddress % si.allocationGranularity));

                        // Check if there is enough left
                        if((mbi.RegionSize - offset) >= size)
                        {
                            // yup there is enough
                            tmpAddress = UIntPtr.Add(tmpAddress, offset);

                            if((long)tmpAddress < (long)baseAddress)
                            {
                                tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

                                if ((long)tmpAddress > (long)baseAddress)
                                    tmpAddress = baseAddress;

                                // decrease tmpAddress until its alligned properly
                                tmpAddress = UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                            }

                            // if the difference is closer then use that
                            if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                                ret = tmpAddress;
                        }
                    }
                    else
                    {
                        tmpAddress = mbi.BaseAddress;

                        if((long)tmpAddress < (long)baseAddress) // try to get it the cloest possible 
                                                                 // (so to the end of the region - size and
                                                                 // aligned by system allocation granularity)
                        {
                            tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - size));

                            if ((long)tmpAddress > (long)baseAddress)
                                tmpAddress = baseAddress;

                            // decrease until aligned properly
                            tmpAddress =
                                UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                        }

                        if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                            ret = tmpAddress;
                    }
                }

                if (mbi.RegionSize % si.allocationGranularity > 0)
                    mbi.RegionSize += si.allocationGranularity - (mbi.RegionSize % si.allocationGranularity);

                previous = current;
                current = new UIntPtr( ((ulong)mbi.BaseAddress) + (ulong)mbi.RegionSize);

                if ((long)current >= (long)maxAddress)
                    return ret;

                if ((long)previous >= (long)current)
                    return ret; // Overflow
            }

            return ret;
        }
#endif

        public static void SuspendProcess(int pid)
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }

        public static void ResumeProcess(int pid)
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);
            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                var suspendCount = 0;
                do
                {
                    suspendCount = ResumeThread(pOpenThread);
                } while (suspendCount > 0);
                CloseHandle(pOpenThread);
            }
        }

#if WINXP
#else
        async Task PutTaskDelay(int delay)
        {
            await Task.Delay(delay);
        }
#endif

        void AppendAllBytes(string path, byte[] bytes)
        {
            using (var stream = new FileStream(path, FileMode.Append))
            {
                stream.Write(bytes, 0, bytes.Length);
            }
        }

        public byte[] FileToBytes(string path, bool dontDelete = false) {
            byte[] newArray = File.ReadAllBytes(path);
            if (!dontDelete)
                File.Delete(path);
            return newArray;
        }

        public string MSize()
        {
            if (mProc.Is64Bit)
                return ("x16");
            else
                return ("x8");
        }

        /// <summary>
        /// Convert a byte array to hex values in a string.
        /// </summary>
        /// <param name="ba">your byte array to convert</param>
        /// <returns></returns>
        public static string ByteArrayToHexString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            int i = 1;
            foreach (byte b in ba)
            {
                if (i == 16)
                {
                    hex.AppendFormat("{0:x2}{1}", b, Environment.NewLine);
                    i = 0;
                }
                else
                    hex.AppendFormat("{0:x2} ", b);
                i++;
            }
            return hex.ToString().ToUpper();
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2} ", b);
            }
            return hex.ToString();
        }

        public ulong GetMinAddress()
        {
            SYSTEM_INFO SI;
            GetSystemInfo(out SI);
            return (ulong)SI.minimumApplicationAddress;
        }

        /// <summary>
        /// Dump memory page by page to a dump.dmp file. Can be used with Cheat Engine.
        /// </summary>
        public bool DumpMemory(string file = "dump.dmp")
        {
            Debug.Write("[DEBUG] memory dump starting... (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
            UIntPtr proc_max_address = sys_info.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            Int64 proc_min_address_l = (Int64)proc_min_address; //(Int64)procs.MainModule.BaseAddress;
            Int64 proc_max_address_l = (Int64)mProc.Process.VirtualMemorySize64 + proc_min_address_l;

            //int arrLength = 0;
            if (File.Exists(file))
                File.Delete(file);


            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            while (proc_min_address_l < proc_max_address_l)
            {
                VirtualQueryEx(mProc.Handle, proc_min_address, out memInfo);
                byte[] buffer = new byte[(Int64)memInfo.RegionSize];
                UIntPtr test = (UIntPtr)((Int64)memInfo.RegionSize);
                UIntPtr test2 = (UIntPtr)((Int64)memInfo.BaseAddress);

                ReadProcessMemory(mProc.Handle, test2, buffer, test, IntPtr.Zero);

                AppendAllBytes(file, buffer); //due to memory limits, we have to dump it then store it in an array.
                //arrLength += buffer.Length;

                proc_min_address_l += (Int64)memInfo.RegionSize;
                proc_min_address = new UIntPtr((ulong)proc_min_address_l);
            }


            Debug.Write("[DEBUG] memory dump completed. Saving dump file to " + file + ". (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
            return true;
        }

        /// <summary>
        /// get a list of available threads in opened process
        /// </summary>
        public void GetThreads()
        {
            if (mProc.Process == null)
            {
                Debug.WriteLine("mProc.Process is null so GetThreads failed.");
                return;
            }

            foreach (ProcessThread thd in mProc.Process.Threads)
            {
                Debug.WriteLine("ID:" + thd.Id + " State:" + thd.ThreadState + " Address:" + thd.StartAddress + " Priority:" + thd.PriorityLevel);
            }
        }

        /// <summary>
        /// Get thread base address by ID. Provided by github.com/osadrac
        /// </summary>
        /// <param name="threadId"></param>
        /// <returns></returns>
        /// <exception cref="Win32Exception"></exception>
        public static IntPtr GetThreadStartAddress(int threadId)
        {
            var hThread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)threadId);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception();
            var buf = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                var result = Imps.NtQueryInformationThread(hThread,
                                 ThreadInfoClass.ThreadQuerySetWin32StartAddress,
                                 buf, IntPtr.Size, IntPtr.Zero);
                if (result != 0)
                    throw new Win32Exception(string.Format("NtQueryInformationThread failed; NTSTATUS = {0:X8}", result));
                return Marshal.ReadIntPtr(buf);
            }
            finally
            {
                CloseHandle(hThread);
                Marshal.FreeHGlobal(buf);
            }
        }

        /// <summary>
        /// suspend a thread by ID
        /// </summary>
        /// <param name="ThreadID">the thread you wish to suspend by ID</param>
        /// <returns></returns>
        public bool SuspendThreadByID(int ThreadID)
        {
            foreach (ProcessThread thd in mProc.Process.Threads)
            {
                if (thd.Id != ThreadID)
                    continue;
                else
                    Debug.WriteLine("Found thread " + ThreadID);

                IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)ThreadID);

                if (threadHandle == IntPtr.Zero)
                    break;

                if (SuspendThread(threadHandle) == -1)
                {
                    Debug.WriteLine("Thread failed to suspend");
                    CloseHandle(threadHandle);
                    break;
                }
                else
                {
                    Debug.WriteLine("Thread suspended!");
                    CloseHandle(threadHandle);
                    return true;
                }
            }
            return false;
        }

    }
}
