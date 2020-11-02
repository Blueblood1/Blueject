using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using static Blueject.Definitions;
using static Blueject.DataClasses;

namespace Blueject
{
    class BInjector
    {
        private Process processMain;
        private IntPtr processHandle;

        public void Inject(Process process, string file)
        {
            processMain = process;
            processHandle = CPlusPlusImports.OpenProcess(processMain, CPlusPlusImports.ProcessAccessFlags.All);

            Byte[] dllBytes = File.ReadAllBytes(file);
            GCHandle dllHandle = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            LoadDLLImage(dllHandle.AddrOfPinnedObject());

            Thread.Sleep(500);
            dllHandle.Free();
            CPlusPlusImports.CloseHandle(processHandle);
        }

        #region Quick Help
        private string ToStringAnsi(byte[] buffer)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte t in buffer)
            {
                if (t == 0)
                {
                    break;
                }

                sb.Append((char)t);
            }

            return sb.ToString();
        }

        private bool StringCompare(char[] str1, char[] str2)
        {
            int min = Math.Min(str1.Length, str2.Length);
            for (var i = 0; i < min; i++)
            {
                if (str1[i] != str2[i])
                {
                    return false;
                }

                if (str1[i] == 0)
                {
                    break;
                }
            }

            return true;
        }

        private PIMAGE_DOS_HEADER GetDHead(IntPtr address)
        {
            return (PIMAGE_DOS_HEADER)address;
        }

        private PIMAGE_NT_HEADERS32 GetNtHead(IntPtr address)
        {
            PIMAGE_DOS_HEADER imageDosHeader = GetDHead(address);
            PIMAGE_NT_HEADERS32 imageNtHeaders = (PIMAGE_NT_HEADERS32)(address + imageDosHeader.Value.e_lfanew);
            return imageNtHeaders;
        }

        private IntPtr AddressSizeToPointer(uint AddressSize, IntPtr baseAddress)
        {
            PIMAGE_NT_HEADERS32 imageNtHeaders = GetNtHead(baseAddress);
            return CPlusPlusImports.ImageRvaToVa(imageNtHeaders.Address, baseAddress, new UIntPtr(AddressSize), IntPtr.Zero);
        }

        private IntPtr GrabMemory(uint size)
        {
            return CPlusPlusImports.VirtualAllocEx(processHandle, UIntPtr.Zero, new IntPtr(size), CPlusPlusImports.AllocationType.Commit | CPlusPlusImports.AllocationType.Reserve, CPlusPlusImports.MemoryProtection.ExecuteReadWrite);
        }

        private IntPtr AllocateMemory(uint size)
        {
            return CPlusPlusImports.VirtualAlloc(IntPtr.Zero, new UIntPtr(size), CPlusPlusImports.AllocationType.Commit | CPlusPlusImports.AllocationType.Reserve, CPlusPlusImports.MemoryProtection.ExecuteReadWrite);
        }

        private uint ProtectionToInt(DataSectionFlags characteristics)
        {
            uint result = 0;
            if (characteristics.HasFlag(DataSectionFlags.MemoryNotCached)) result |= 0x200;

            if (characteristics.HasFlag(DataSectionFlags.MemoryExecute))
            {
                if (characteristics.HasFlag(DataSectionFlags.MemoryRead))
                {
                    if (characteristics.HasFlag(DataSectionFlags.MemoryWrite)) result |= 0x40;
                    else result |= 0x20;
                }
                else if (characteristics.HasFlag(DataSectionFlags.MemoryWrite)) result |= 0x80;
                else result |= 0x10;
            }
            else if (characteristics.HasFlag(DataSectionFlags.MemoryRead))
            {
                if (characteristics.HasFlag(DataSectionFlags.MemoryWrite)) result |= 0x04;
                else result |= 0x02;
            }
            else if (characteristics.HasFlag(DataSectionFlags.MemoryWrite)) result |= 0x08;
            else result |= 0x01;

            return result;
        }
        #endregion

        #region Memory Mangement 
        private void LoadDLLImage(IntPtr baseAddress)
        {
            PIMAGE_NT_HEADERS32 imageHeaders = GetNtHead(baseAddress);
            PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)(imageHeaders.Address + 24 + imageHeaders.Value.FileHeader.SizeOfOptionalHeader);

            uint addressHighPoint = unchecked((uint)-1);
            uint addressLowPoint = 0u;

            for (uint i = 0; i < imageHeaders.Value.FileHeader.NumberOfSections; i++)
            {
                if (imageSectionHeader[i].VirtualSize == 0) continue;
                if (imageSectionHeader[i].VirtualAddress < addressHighPoint) addressHighPoint = imageSectionHeader[i].VirtualAddress;
                if (imageSectionHeader[i].VirtualAddress + imageSectionHeader[i].VirtualSize > addressLowPoint) addressLowPoint = imageSectionHeader[i].VirtualAddress + imageSectionHeader[i].VirtualSize;
            }
            uint addressSize = addressLowPoint - addressHighPoint;

            IntPtr allocatedMemory = GrabMemory(addressSize);
            parseImportTable(baseAddress);
            parseImportTableDelayed(baseAddress, allocatedMemory);
            procLocations(baseAddress, allocatedMemory);
            procFields(baseAddress, allocatedMemory);
            procEntries(baseAddress, allocatedMemory);

            if (imageHeaders.Value.OptionalHeader.AddressOfEntryPoint > 0)
            {
                int dllEntryPoint = allocatedMemory.ToInt32() + (int)imageHeaders.Value.OptionalHeader.AddressOfEntryPoint;

                TryEntryPoint(allocatedMemory, (uint)dllEntryPoint);
            }
        }

        private void parseImportTable(IntPtr baseAddress)
        {
            var imageNtHeaders = GetNtHead(baseAddress);

            if (imageNtHeaders.Value.OptionalHeader.ImportTable.Size > 0)
            {
                var imageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)AddressSizeToPointer(imageNtHeaders.Value.OptionalHeader.ImportTable.VirtualAddress, baseAddress);

                if (imageImportDescriptor != null)
                {
                    for (; imageImportDescriptor.Value.Name > 0; imageImportDescriptor++)
                    {
                        var moduleName = (PCHAR)AddressSizeToPointer(imageImportDescriptor.Value.Name, baseAddress);
                        if (moduleName == null)
                        {
                            continue;
                        }

                        if (moduleName.ToString().Contains("-ms-win-crt-"))
                        {
                            moduleName = new PCHAR("ucrtbase.dll");
                        }

                        var moduleBase = GetLibraryHandle(moduleName.ToString());
                        if (moduleBase == IntPtr.Zero)
                        {
                            LoadInjectLibrary(moduleName.ToString());
                            moduleBase = GetLibraryHandle(moduleName.ToString());
                        }

                        PIMAGE_THUNK_DATA imageThunkData;
                        PIMAGE_THUNK_DATA imageFuncData;

                        if (imageImportDescriptor.Value.OriginalFirstThunk > 0)
                        {
                            imageThunkData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageImportDescriptor.Value.OriginalFirstThunk, baseAddress);
                            imageFuncData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageImportDescriptor.Value.FirstThunk, baseAddress);
                        }
                        else
                        {
                            imageThunkData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageImportDescriptor.Value.FirstThunk, baseAddress);
                            imageFuncData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageImportDescriptor.Value.FirstThunk, baseAddress);
                        }

                        for (; imageThunkData.Value.AddressOfData > 0; imageThunkData++, imageFuncData++)
                        {
                            IntPtr functionAddress;
                            var bSnapByOrdinal = (imageThunkData.Value.Ordinal & 0x80000000) != 0;

                            if (bSnapByOrdinal)
                            {
                                var ordinal = (short)(imageThunkData.Value.Ordinal & 0xffff);
                                functionAddress = GetProcessLibraryAddress(moduleBase, new PCHAR(ordinal));
                            }
                            else
                            {
                                var imageImportByName = (PIMAGE_IMPORT_BY_NAME)AddressSizeToPointer(imageFuncData.Value.Ordinal, baseAddress);
                                var mameOfImport = (PCHAR)imageImportByName.Address + 2;
                                functionAddress = GetProcessLibraryAddress(moduleBase, mameOfImport);
                            }
                            Marshal.WriteInt32(imageFuncData.Address, functionAddress.ToInt32());
                        }
                    }
                }
            }
        }

        private void parseImportTableDelayed(IntPtr baseAddress, IntPtr remoteAddress)
        {
            PIMAGE_NT_HEADERS32 imageNtHeaders = GetNtHead(baseAddress);

            if (imageNtHeaders.Value.OptionalHeader.DelayImportDescriptor.Size > 0)
            {
                PIMAGE_IMPORT_DESCRIPTOR imageDelayedImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)AddressSizeToPointer(imageNtHeaders.Value.OptionalHeader.DelayImportDescriptor.VirtualAddress, baseAddress);

                if (imageDelayedImportDescriptor != null)
                {
                    for (; imageDelayedImportDescriptor.Value.Name > 0; imageDelayedImportDescriptor++)
                    {
                        var moduleName = (PCHAR)AddressSizeToPointer(imageDelayedImportDescriptor.Value.Name, baseAddress);
                        if (moduleName == null)
                        {
                            continue;
                        }

                        var moduleBase = GetLibraryHandle(moduleName.ToString());
                        if (moduleBase == IntPtr.Zero)
                        {
                            LoadInjectLibrary(moduleName.ToString());
                            moduleBase = GetLibraryHandle(moduleName.ToString());

                            if (moduleBase == IntPtr.Zero)
                            {
                                continue;
                            }
                        }

                        PIMAGE_THUNK_DATA imageThunkData = null;
                        PIMAGE_THUNK_DATA imageFuncData = null;

                        if (imageDelayedImportDescriptor.Value.OriginalFirstThunk > 0)
                        {
                            imageThunkData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageDelayedImportDescriptor.Value.OriginalFirstThunk, baseAddress);
                            imageFuncData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageDelayedImportDescriptor.Value.FirstThunk, baseAddress);
                        }
                        else
                        {
                            imageThunkData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageDelayedImportDescriptor.Value.FirstThunk, baseAddress);
                            imageFuncData = (PIMAGE_THUNK_DATA)AddressSizeToPointer(imageDelayedImportDescriptor.Value.FirstThunk, baseAddress);
                        }

                        for (; imageThunkData.Value.AddressOfData > 0; imageThunkData++, imageFuncData++)
                        {
                            IntPtr functionAddress;
                            var bSnapByOrdinal = ((imageThunkData.Value.Ordinal & 0x80000000) != 0);

                            if (bSnapByOrdinal)
                            {
                                var ordinal = (short)(imageThunkData.Value.Ordinal & 0xffff);
                                functionAddress = GetProcessLibraryAddress(moduleBase, new PCHAR(ordinal));
                            }
                            else
                            {
                                var imageImportByName = (PIMAGE_IMPORT_BY_NAME)AddressSizeToPointer(imageFuncData.Value.Ordinal, baseAddress);
                                var mameOfImport = (PCHAR)imageImportByName.Address + 2;
                                functionAddress = GetProcessLibraryAddress(moduleBase, mameOfImport);
                            }

                            Marshal.WriteInt32(imageFuncData.Address, functionAddress.ToInt32());
                        }
                    }

                }
            }
        }

        private void procLocations(IntPtr baseAddress, IntPtr remoteAddress)
        {
            PIMAGE_NT_HEADERS32 imageNtHeaders = GetNtHead(baseAddress);

            uint imageBaseDelta = (uint)(remoteAddress.ToInt32() - imageNtHeaders.Value.OptionalHeader.ImageBase);
            uint relocationSize = imageNtHeaders.Value.OptionalHeader.BaseRelocationTable.Size;

            if (relocationSize > 0)
            {
                PIMAGE_BASE_RELOCATION relocationDirectory = (PIMAGE_BASE_RELOCATION)AddressSizeToPointer(imageNtHeaders.Value.OptionalHeader.BaseRelocationTable.VirtualAddress, baseAddress);

                if (relocationDirectory != null)
                {
                    PBYTE relocationEnd = (PBYTE)relocationDirectory.Address + (int)relocationSize;

                    while (relocationDirectory.Address.ToInt64() < relocationEnd.Address.ToInt64())
                    {
                        PBYTE relocBase = (PBYTE)AddressSizeToPointer(relocationDirectory.Value.VirtualAddress, baseAddress);
                        UInt32 numRelocs = (relocationDirectory.Value.SizeOfBlock - 8) >> 1;
                        PWORD relocationData = (PWORD)((relocationDirectory + 1).Address);

                        for (uint i = 0; i < numRelocs; i++, relocationData++)
                        {
                            ShiftProcess(imageBaseDelta, relocationData.Value, relocBase);
                        }

                        relocationDirectory = (PIMAGE_BASE_RELOCATION)relocationData.Address;
                    }
                }
            }
        }

        private void procFields(IntPtr baseAddress, IntPtr remoteAddress)
        {
            PIMAGE_NT_HEADERS32 imageNtHeaders = GetNtHead(baseAddress);

            PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)(imageNtHeaders.Address + 24 + imageNtHeaders.Value.FileHeader.SizeOfOptionalHeader);
            for (ushort i = 0; i < imageNtHeaders.Value.FileHeader.NumberOfSections; i++)
            {
                if (StringCompare(".reloc".ToCharArray(), imageSectionHeader[i].Name))
                {
                    continue;
                }

                DataSectionFlags characteristics = imageSectionHeader[i].Characteristics;
                if (characteristics.HasFlag(DataSectionFlags.MemoryRead) || characteristics.HasFlag(DataSectionFlags.MemoryWrite) || characteristics.HasFlag(DataSectionFlags.MemoryExecute))
                {
                    uint protection = ProtectionToInt(imageSectionHeader[i].Characteristics);
                    WriteSelection(imageSectionHeader[i].Name, baseAddress, remoteAddress, imageSectionHeader[i].PointerToRawData, imageSectionHeader[i].VirtualAddress, imageSectionHeader[i].SizeOfRawData, imageSectionHeader[i].VirtualSize, protection);
                }
            }
        }

        private void procEntries(IntPtr baseAddress, IntPtr remoteAddress)
        {
            UIntPtr dwRead;
            PIMAGE_NT_HEADERS32 imageHeaders = GetNtHead(baseAddress);
            PIMAGE_TLS_DIRECTORY32 tlsDirectory = (PIMAGE_TLS_DIRECTORY32)AddressSizeToPointer(imageHeaders.Value.OptionalHeader.TLSTable.VirtualAddress, baseAddress);

            byte[] buffer = new byte[0xFF * 4];
            CPlusPlusImports.ReadProcessMemory(processHandle, new IntPtr(tlsDirectory.Value.AddressOfCallBacks), buffer, out dwRead);

            PDWORD tLSCallbacks = new PDWORD(buffer);

            bool result = true;
            for (uint i = 0; tLSCallbacks[i] > 0; i++)
            {
                result = TryEntryPoint(remoteAddress, tLSCallbacks[i]);

                if (!result)
                {
                    break;
                }
            }
        }

        #region Sub Memory
        private void ShiftProcess(uint imageBaseDelta, ushort data, PBYTE relocationBase)
        {
            PSHORT raw;
            PDWORD raw2;

            switch ((data >> 12) & 0xF)
            {
                case 1:
                    raw = (PSHORT)(relocationBase + (data & 0xFFF)).Address;
                    Marshal.WriteInt16(raw.Address, unchecked((short)(raw.Value + (uint)((ushort)((imageBaseDelta >> 16) & 0xffff)))));
                    break;

                case 2:
                    raw = (PSHORT)(relocationBase + (data & 0xFFF)).Address;
                    Marshal.WriteInt16(raw.Address, unchecked((short)(raw.Value + (uint)((ushort)(imageBaseDelta & 0xffff)))));
                    break;

                case 3:
                    raw2 = (PDWORD)(relocationBase + (data & 0xFFF)).Address;
                    Marshal.WriteInt32(raw2.Address, unchecked((int)(raw2.Value + imageBaseDelta)));
                    break;

                case 10:
                    raw2 = (PDWORD)(relocationBase + (data & 0xFFF)).Address;
                    Marshal.WriteInt32(raw2.Address, unchecked((int)(raw2.Value + imageBaseDelta)));
                    break;

                case 0:
                    break;

                case 4:
                    break;

                default:
                    break;
            }
        }

        private void LoadInjectLibrary(string dependency)
        {
            IntPtr procAddress = CPlusPlusImports.GetProcAddress(CPlusPlusImports.GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            IntPtr lpAddress = GrabMemory((uint)dependency.Length);
            byte[] buffer = Encoding.ASCII.GetBytes(dependency);

            UIntPtr bytesWritten;
            bool result = CPlusPlusImports.WriteProcessMemory(processHandle, lpAddress, buffer, buffer.Length, out bytesWritten);

            if (result)
            {
                var hHandle = CPlusPlusImports.CreateRemoteThread(processHandle, IntPtr.Zero, 0, procAddress, lpAddress, 0, IntPtr.Zero);
                CPlusPlusImports.WaitForSingleObject(hHandle, 5000);
            }

            CPlusPlusImports.VirtualFreeEx(processHandle, lpAddress, 0, CPlusPlusImports.FreeType.Release);
        }

        private IntPtr GetLibraryHandle(string module)
        {
            IntPtr dwModuleHandle = IntPtr.Zero;
            IntPtr hHeap = CPlusPlusImports.GetProcessHeap();
            uint dwSize = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            PPROCESS_BASIC_INFORMATION pbi = (PPROCESS_BASIC_INFORMATION)CPlusPlusImports.HeapAlloc(hHeap, 0x8, new UIntPtr(dwSize));

            uint dwSizeNeeded;
            int dwStatus = CPlusPlusImports.NtQueryInformationProcess(processHandle, 0, pbi.Address, dwSize, out dwSizeNeeded);

            if (dwStatus >= 0 && dwSize < dwSizeNeeded)
            {
                if (pbi != null)
                {
                    CPlusPlusImports.HeapFree(hHeap, 0, pbi.Address);
                }

                pbi = (PPROCESS_BASIC_INFORMATION)CPlusPlusImports.HeapAlloc(hHeap, 0x8, new UIntPtr(dwSize));

                dwStatus = CPlusPlusImports.NtQueryInformationProcess(processHandle, 0, pbi.Address, dwSizeNeeded, out dwSizeNeeded);
            }

            if (dwStatus >= 0)
            {
                if (pbi.Value.PebBaseAddress != IntPtr.Zero)
                {
                    UIntPtr dwBytesRead;
                    uint pebLdrAddress;

                    if (CPlusPlusImports.ReadProcessMemory(processHandle, pbi.Value.PebBaseAddress + 12, out pebLdrAddress, out dwBytesRead))
                    {
                        var pLdrListHead = pebLdrAddress + 0x0C;
                        var pLdrCurrentNode = pebLdrAddress + 0x0C;

                        do
                        {
                            uint lstEntryAddress;
                            if (!CPlusPlusImports.ReadProcessMemory(processHandle, new IntPtr(pLdrCurrentNode), out lstEntryAddress, out dwBytesRead))
                            {
                                CPlusPlusImports.HeapFree(hHeap, 0, pbi.Address);
                            }
                            pLdrCurrentNode = lstEntryAddress;

                            UNICODE_STRING baseDllName;
                            CPlusPlusImports.ReadProcessMemory(processHandle, new IntPtr(lstEntryAddress) + 0x2C, out baseDllName, out dwBytesRead);

                            string strBaseDllName = string.Empty;

                            if (baseDllName.Length > 0)
                            {
                                byte[] buffer = new byte[baseDllName.Length];
                                CPlusPlusImports.ReadProcessMemory(processHandle, baseDllName.Buffer, buffer, out dwBytesRead);
                                strBaseDllName = Encoding.Unicode.GetString(buffer);
                            }

                            uint dllBase;
                            uint sizeOfImage;

                            CPlusPlusImports.ReadProcessMemory(processHandle, new IntPtr(lstEntryAddress) + 0x18, out dllBase, out dwBytesRead);
                            CPlusPlusImports.ReadProcessMemory(processHandle, new IntPtr(lstEntryAddress) + 0x20, out sizeOfImage, out dwBytesRead);

                            if (dllBase != 0 && sizeOfImage != 0)
                            {
                                if (string.Equals(strBaseDllName, module, StringComparison.OrdinalIgnoreCase))
                                {
                                    dwModuleHandle = new IntPtr(dllBase);
                                    break;
                                }
                            }

                        } while (pLdrListHead != pLdrCurrentNode);
                    }
                }
            }

            if (pbi != null)
            {
                CPlusPlusImports.HeapFree(hHeap, 0, pbi.Address);
            }

            return dwModuleHandle;
        }

        private IntPtr GetProcessLibraryAddress(IntPtr moduleBase, PCHAR procName)
        {
            IntPtr pFunc = IntPtr.Zero;
            IMAGE_DOS_HEADER hdrDos;
            IMAGE_NT_HEADERS32 hdrNt32;
            UIntPtr dwRead;
            CPlusPlusImports.ReadProcessMemory(processHandle, moduleBase, out hdrDos, out dwRead);
            CPlusPlusImports.ReadProcessMemory(processHandle, moduleBase + hdrDos.e_lfanew, out hdrNt32, out dwRead);

            uint expBase = hdrNt32.OptionalHeader.ExportTable.VirtualAddress;
            if (expBase > 0)
            {
                uint expSize = hdrNt32.OptionalHeader.ExportTable.Size;
                PIMAGE_EXPORT_DIRECTORY expData = (PIMAGE_EXPORT_DIRECTORY)AllocateMemory(expSize);
                CPlusPlusImports.ReadProcessMemory(processHandle, moduleBase + (int)expBase, expData.Address, (int)expSize, out dwRead);

                PWORD pAddressOfOrds = (PWORD)(expData.Address + (int)expData.Value.AddressOfNameOrdinals - (int)expBase);
                PDWORD pAddressOfNames = (PDWORD)(expData.Address + (int)expData.Value.AddressOfNames - (int)expBase);
                PDWORD pAddressOfFuncs = (PDWORD)(expData.Address + (int)expData.Value.AddressOfFunctions - (int)expBase);


                for (uint i = 0; i < expData.Value.NumberOfFunctions; i++)
                {
                    ushort ordIndex;
                    PCHAR pName = null;

                    if (new PDWORD(procName.Address).Value <= 0xFFFF)
                    {
                        ordIndex = unchecked((ushort)i);
                    }
                    else if (new PDWORD(procName.Address).Value > 0xFFFF && i < expData.Value.NumberOfNames)
                    {
                        pName = (PCHAR)new IntPtr(pAddressOfNames[i] + expData.Address.ToInt32() - expBase);
                        ordIndex = pAddressOfOrds[i];
                    }
                    else
                    {
                        return IntPtr.Zero;
                    }

                    if ((new PDWORD(procName.Address).Value <= 0xFFFF && new PDWORD(procName.Address).Value == ordIndex + expData.Value.Base) || (new PDWORD(procName.Address).Value > 0xFFFF && pName.ToString() == procName.ToString()))
                    {
                        pFunc = moduleBase + (int)pAddressOfFuncs[ordIndex];

                        if (pFunc.ToInt64() >= (moduleBase + (int)expBase).ToInt64() && pFunc.ToInt64() <= (moduleBase + (int)expBase + (int)expSize).ToInt64())
                        {
                            byte[] forwardStr = new byte[255];
                            CPlusPlusImports.ReadProcessMemory(processHandle, pFunc, forwardStr, out dwRead);

                            string chainExp = ToStringAnsi(forwardStr);

                            string strDll = chainExp.Substring(0, chainExp.IndexOf(".")) + ".dll";
                            string strName = chainExp.Substring(chainExp.IndexOf(".") + 1);

                            IntPtr hChainMod = GetLibraryHandle(strDll);
                            if (hChainMod == IntPtr.Zero)
                            {
                                LoadInjectLibrary(strDll);
                            }

                            if (strName.StartsWith("#"))
                            {
                                pFunc = GetProcessLibraryAddress(hChainMod, new PCHAR(strName) + 1);
                            }
                            else
                            {
                                pFunc = GetProcessLibraryAddress(hChainMod, new PCHAR(strName));
                            }
                        }

                        break;
                    }
                }

                CPlusPlusImports.VirtualFree(expData.Address, 0, CPlusPlusImports.FreeType.Release);
            }

            return pFunc;
        }

        private void WriteSelection(char[] name, IntPtr baseAddress, IntPtr remoteAddress, ulong rawData, ulong virtualAddress, ulong rawSize, ulong virtualSize, uint protectFlag)
        {
            UIntPtr lpNumberOfBytesWritten;
            uint dwOldProtect;

            CPlusPlusImports.WriteProcessMemory(processHandle, new IntPtr(remoteAddress.ToInt64() + (long)virtualAddress), new IntPtr(baseAddress.ToInt64() + (long)rawData), new IntPtr((long)rawSize), out lpNumberOfBytesWritten);
            CPlusPlusImports.VirtualProtectEx(processHandle, new IntPtr(remoteAddress.ToInt64() + (long)virtualAddress), new UIntPtr(virtualSize), protectFlag, out dwOldProtect);
        }

        private bool TryEntryPoint(IntPtr baseAddress, uint entrypoint)
        {
            var buffer = new List<byte>();
            buffer.Add(0x68);
            buffer.AddRange(BitConverter.GetBytes(baseAddress.ToInt32()));
            buffer.Add(0x68);
            buffer.AddRange(BitConverter.GetBytes(1));
            buffer.Add(0x68);
            buffer.AddRange(BitConverter.GetBytes(0));
            buffer.Add(0xB8);
            buffer.AddRange(BitConverter.GetBytes(entrypoint));
            buffer.Add(0xFF);
            buffer.Add(0xD0);
            buffer.Add(0x33);
            buffer.Add(0xC0);
            buffer.Add(0xC2);
            buffer.Add(0x04);
            buffer.Add(0x00);

            return CreatePossibleThread(buffer.ToArray());
        }

        private bool CreatePossibleThread(byte[] threadData)
        {
            IntPtr lpAddress = GrabMemory((uint)threadData.Length);
            UIntPtr bytesWritten;
            bool result = CPlusPlusImports.WriteProcessMemory(processHandle, lpAddress, threadData, threadData.Length, out bytesWritten);

            if (result)
            {
                IntPtr hHandle = CPlusPlusImports.CreateRemoteThread(processHandle, IntPtr.Zero, 0, lpAddress, IntPtr.Zero, 0, IntPtr.Zero);
                CPlusPlusImports.WaitForSingleObject(hHandle, 4000);
                CPlusPlusImports.VirtualFreeEx(processHandle, lpAddress, 0, CPlusPlusImports.FreeType.Release);
            }
            return result;
        }
        #endregion
        #endregion
    }

    public class ManagedPtr<T> where T : struct
    {
        public IntPtr Address { get; }

        public T Value
        {
            get { return this[0]; }
        }

        private int? _structSize;

        public int StructSize
        {
            get
            {
                if (_structSize == null)
                {
                    _structSize = Marshal.SizeOf(typeof(T));
                }

                return _structSize.Value;
            }
        }

        private static T GetStructure(IntPtr address)
        {
            return (T)Marshal.PtrToStructure(address, typeof(T));
        }

        public T this[uint index]
        {
            get { return GetStructure(Address + (int)index * StructSize); }
        }

        public static ManagedPtr<T> operator +(ManagedPtr<T> c1, int c2)
        {
            return new ManagedPtr<T>(c1.Address + c2 * c1.StructSize);
        }

        public static ManagedPtr<T> operator ++(ManagedPtr<T> a)
        {
            return a + 1;
        }

        public static ManagedPtr<T> operator -(ManagedPtr<T> c1, int c2)
        {
            return new ManagedPtr<T>(c1.Address - c2 * c1.StructSize);
        }

        public static ManagedPtr<T> operator --(ManagedPtr<T> a)
        {
            return a - 1;
        }

        public static explicit operator ManagedPtr<T>(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }

            return new ManagedPtr<T>(ptr);
        }

        public static explicit operator IntPtr(ManagedPtr<T> ptr)
        {
            return ptr.Address;
        }

        private GCHandle _handle;

        private bool _freeHandle;

        public ManagedPtr(IntPtr address)
        {
            Address = address;
        }

        public ManagedPtr(object value, bool freeHandle = true)
        {
            if (value == null)
            {
                throw new InvalidOperationException("Cannot create a pointer of type null");
            }

            try
            {
                _handle = GCHandle.Alloc(value, GCHandleType.Pinned);
            }
            catch (Exception)
            {
                throw new InvalidOperationException($"Cannot create a pointer of type {value.GetType().Name}");
            }

            _freeHandle = freeHandle;
            Address = _handle.AddrOfPinnedObject();
        }

        ~ManagedPtr()
        {
            if (_handle.IsAllocated && _freeHandle)
            {
                _handle.Free();
            }
        }
    }

    public class Definitions
    {
        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,

            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,

            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,

            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,

            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,

            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,

            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,

            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,

            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,

            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,

            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,

            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,

            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,

            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,

            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,

            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,

            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,

            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,

            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,

            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,

            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,

            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,

            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,

            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,

            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,

            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,

            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,

            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,

            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,

            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,

            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,

            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] public char[] e_magic; // Magic number
            public UInt16 e_cblp; // Bytes on last page of file
            public UInt16 e_cp; // Pages in file
            public UInt16 e_crlc; // Relocations
            public UInt16 e_cparhdr; // Size of header in paragraphs
            public UInt16 e_minalloc; // Minimum extra paragraphs needed
            public UInt16 e_maxalloc; // Maximum extra paragraphs needed
            public UInt16 e_ss; // Initial (relative) SS value
            public UInt16 e_sp; // Initial SP value
            public UInt16 e_csum; // Checksum
            public UInt16 e_ip; // Initial IP value
            public UInt16 e_cs; // Initial (relative) CS value
            public UInt16 e_lfarlc; // File address of relocation table
            public UInt16 e_ovno; // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public UInt16[] e_res1; // Reserved words
            public UInt16 e_oemid; // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo; // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public UInt16[] e_res2; // Reserved words
            public Int32 e_lfanew; // File address of new exe header

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)] public MagicType Magic;

            [FieldOffset(2)] public byte MajorLinkerVersion;

            [FieldOffset(3)] public byte MinorLinkerVersion;

            [FieldOffset(4)] public uint SizeOfCode;

            [FieldOffset(8)] public uint SizeOfInitializedData;

            [FieldOffset(12)] public uint SizeOfUninitializedData;

            [FieldOffset(16)] public uint AddressOfEntryPoint;

            [FieldOffset(20)] public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)] public uint BaseOfData;

            [FieldOffset(28)] public uint ImageBase;

            [FieldOffset(32)] public uint SectionAlignment;

            [FieldOffset(36)] public uint FileAlignment;

            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)] public ushort MajorImageVersion;

            [FieldOffset(46)] public ushort MinorImageVersion;

            [FieldOffset(48)] public ushort MajorSubsystemVersion;

            [FieldOffset(50)] public ushort MinorSubsystemVersion;

            [FieldOffset(52)] public uint Win32VersionValue;

            [FieldOffset(56)] public uint SizeOfImage;

            [FieldOffset(60)] public uint SizeOfHeaders;

            [FieldOffset(64)] public uint CheckSum;

            [FieldOffset(68)] public SubSystemType Subsystem;

            [FieldOffset(70)] public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)] public uint SizeOfStackReserve;

            [FieldOffset(76)] public uint SizeOfStackCommit;

            [FieldOffset(80)] public uint SizeOfHeapReserve;

            [FieldOffset(84)] public uint SizeOfHeapCommit;

            [FieldOffset(88)] public uint LoaderFlags;

            [FieldOffset(92)] public uint NumberOfRvaAndSizes;

            [FieldOffset(96)] public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)] public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)] public MagicType Magic;

            [FieldOffset(2)] public byte MajorLinkerVersion;

            [FieldOffset(3)] public byte MinorLinkerVersion;

            [FieldOffset(4)] public uint SizeOfCode;

            [FieldOffset(8)] public uint SizeOfInitializedData;

            [FieldOffset(12)] public uint SizeOfUninitializedData;

            [FieldOffset(16)] public uint AddressOfEntryPoint;

            [FieldOffset(20)] public uint BaseOfCode;

            [FieldOffset(24)] public ulong ImageBase;

            [FieldOffset(32)] public uint SectionAlignment;

            [FieldOffset(36)] public uint FileAlignment;

            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)] public ushort MajorImageVersion;

            [FieldOffset(46)] public ushort MinorImageVersion;

            [FieldOffset(48)] public ushort MajorSubsystemVersion;

            [FieldOffset(50)] public ushort MinorSubsystemVersion;

            [FieldOffset(52)] public uint Win32VersionValue;

            [FieldOffset(56)] public uint SizeOfImage;

            [FieldOffset(60)] public uint SizeOfHeaders;

            [FieldOffset(64)] public uint CheckSum;

            [FieldOffset(68)] public SubSystemType Subsystem;

            [FieldOffset(70)] public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)] public ulong SizeOfStackReserve;

            [FieldOffset(80)] public ulong SizeOfStackCommit;

            [FieldOffset(88)] public ulong SizeOfHeapReserve;

            [FieldOffset(96)] public ulong SizeOfHeapCommit;

            [FieldOffset(104)] public uint LoaderFlags;

            [FieldOffset(108)] public uint NumberOfRvaAndSizes;

            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)] public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            [FieldOffset(0)] [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public char[] Signature;

            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

            private string _Signature
            {
                get { return new string(Signature); }
            }

            public bool isValid
            {
                get
                {
                    return _Signature == "PE\0\0"
                        /*&& (OptionalHeader.Magic == PE.MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC || OptionalHeader.Magic == PE.MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)*/;
                }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)] [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public char[] Signature;

            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

            private string _Signature
            {
                get { return new string(Signature); }
            }

            public bool isValid
            {
                get
                {
                    return _Signature == "PE\0\0"
                        /*&& (OptionalHeader.Magic == PE.MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC || OptionalHeader.Magic == PE.MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)*/;
                }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)] [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public char[] Name;

            [FieldOffset(8)] public UInt32 VirtualSize;

            [FieldOffset(12)] public UInt32 VirtualAddress;

            [FieldOffset(16)] public UInt32 SizeOfRawData;

            [FieldOffset(20)] public UInt32 PointerToRawData;

            [FieldOffset(24)] public UInt32 PointerToRelocations;

            [FieldOffset(28)] public UInt32 PointerToLinenumbers;

            [FieldOffset(32)] public UInt16 NumberOfRelocations;

            [FieldOffset(34)] public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)] public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            [FieldOffset(0)] public uint Characteristics;

            [FieldOffset(0)] public uint OriginalFirstThunk;

            [FieldOffset(4)] public uint TimeDateStamp;

            [FieldOffset(8)] public uint ForwarderChain;

            [FieldOffset(12)] public uint Name;

            [FieldOffset(16)] public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;

            public int Size
            {
                get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA
        {
            [FieldOffset(0)] public uint ForwarderString; // PBYTE 

            [FieldOffset(0)] public uint Function; // PDWORD

            [FieldOffset(0)] public uint Ordinal;

            [FieldOffset(0)] public uint AddressOfData; // PIMAGE_IMPORT_BY_NAME
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions; // RVA from base of image
            public UInt32 AddressOfNames; // RVA from base of image
            public UInt32 AddressOfNameOrdinals; // RVA from base of image
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_BY_NAME
        {
            public short Hint;
            public char Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public UInt32 VirtualAddress;
            public UInt32 SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_TLS_DIRECTORY32
        {
            public UInt32 StartAddressOfRawData;
            public UInt32 EndAddressOfRawData;
            public UInt32 AddressOfIndex; // PDWORD
            public UInt32 AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *
            public UInt32 SizeOfZeroFill;
            public UInt32 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY32
        {
            public UInt32 Size;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 GlobalFlagsClear;
            public UInt32 GlobalFlagsSet;
            public UInt32 CriticalSectionDefaultTimeout;
            public UInt32 DeCommitFreeBlockThreshold;
            public UInt32 DeCommitTotalFreeThreshold;
            public UInt32 LockPrefixTable;                // VA
            public UInt32 MaximumAllocationSize;
            public UInt32 VirtualMemoryThreshold;
            public UInt32 ProcessHeapFlags;
            public UInt32 ProcessAffinityMask;
            public UInt16 CSDVersion;
            public UInt16 Reserved1;
            public UInt32 EditList;                       // VA
            public UInt32 SecurityCookie;                 // VA
            public UInt32 SEHandlerTable;                 // VA
            public UInt32 SEHandlerCount;
            public UInt32 GuardCFCheckFunctionPointer;    // VA
            public UInt32 Reserved2;
            public UInt32 GuardCFFunctionTable;           // VA
            public UInt32 GuardCFFunctionCount;
            public UInt32 GuardFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint DateTimeLow;
            public uint DateTimeHigh;
        }
    }

    public class DataClasses
    {
        public class PIMAGE_DOS_HEADER : ManagedPtr<IMAGE_DOS_HEADER>
        {
            public PIMAGE_DOS_HEADER(IntPtr address) : base(address)
            {
            }

            public PIMAGE_DOS_HEADER(object value) : base(value)
            {
            }

            public static explicit operator PIMAGE_DOS_HEADER(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_DOS_HEADER(ptr);
            }
        }

        public class PIMAGE_NT_HEADERS32 : ManagedPtr<IMAGE_NT_HEADERS32>
        {
            public PIMAGE_NT_HEADERS32(IntPtr address) : base(address)
            {
            }

            public PIMAGE_NT_HEADERS32(object value) : base(value)
            {
            }

            public static explicit operator PIMAGE_NT_HEADERS32(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_NT_HEADERS32(ptr);
            }
        }

        public class PCHAR : ManagedPtr<char>
        {
            public PCHAR(IntPtr address) : base(address)
            {
            }

            public PCHAR(object value) : base(value)
            {
            }

            public PCHAR(string value) : base(Encoding.UTF8.GetBytes(value))
            {
            }

            public static PCHAR operator +(PCHAR c1, int c2)
            {
                return new PCHAR(c1.Address + c2 * c1.StructSize);
            }

            public static PCHAR operator ++(PCHAR a)
            {
                return a + 1;
            }

            public static explicit operator PCHAR(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PCHAR(ptr);
            }

            public override string ToString()
            {
                return Marshal.PtrToStringAnsi(Address) ?? string.Empty;
            }
        }

        public class PPROCESS_BASIC_INFORMATION : ManagedPtr<PROCESS_BASIC_INFORMATION>
        {
            public PPROCESS_BASIC_INFORMATION(IntPtr address) : base(address)
            {
            }

            public PPROCESS_BASIC_INFORMATION(object value) : base(value)
            {
            }

            public static explicit operator PPROCESS_BASIC_INFORMATION(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PPROCESS_BASIC_INFORMATION(ptr);
            }
        }

        public class PIMAGE_IMPORT_DESCRIPTOR : ManagedPtr<IMAGE_IMPORT_DESCRIPTOR>
        {
            public PIMAGE_IMPORT_DESCRIPTOR(IntPtr address) : base(address)
            {
            }

            public PIMAGE_IMPORT_DESCRIPTOR(object value) : base(value)
            {
            }

            public static PIMAGE_IMPORT_DESCRIPTOR operator +(PIMAGE_IMPORT_DESCRIPTOR c1, int c2)
            {
                return new PIMAGE_IMPORT_DESCRIPTOR(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_IMPORT_DESCRIPTOR operator ++(PIMAGE_IMPORT_DESCRIPTOR a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_IMPORT_DESCRIPTOR(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_IMPORT_DESCRIPTOR(ptr);
            }
        }

        public class PIMAGE_SECTION_HEADER : ManagedPtr<IMAGE_SECTION_HEADER>
        {
            public PIMAGE_SECTION_HEADER(IntPtr address) : base(address)
            {
            }

            public PIMAGE_SECTION_HEADER(object value) : base(value)
            {
            }

            public static explicit operator PIMAGE_SECTION_HEADER(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_SECTION_HEADER(ptr);
            }
        }

        public class PIMAGE_THUNK_DATA : ManagedPtr<IMAGE_THUNK_DATA>
        {
            public PIMAGE_THUNK_DATA(IntPtr address) : base(address)
            {
            }

            public PIMAGE_THUNK_DATA(object value) : base(value)
            {
            }

            public static PIMAGE_THUNK_DATA operator +(PIMAGE_THUNK_DATA c1, int c2)
            {
                return new PIMAGE_THUNK_DATA(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_THUNK_DATA operator ++(PIMAGE_THUNK_DATA a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_THUNK_DATA(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_THUNK_DATA(ptr);
            }
        }

        public class PIMAGE_EXPORT_DIRECTORY : ManagedPtr<IMAGE_EXPORT_DIRECTORY>
        {
            public PIMAGE_EXPORT_DIRECTORY(IntPtr address) : base(address)
            {
            }

            public PIMAGE_EXPORT_DIRECTORY(object value) : base(value)
            {
            }

            public static PIMAGE_EXPORT_DIRECTORY operator +(PIMAGE_EXPORT_DIRECTORY c1, int c2)
            {
                return new PIMAGE_EXPORT_DIRECTORY(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_EXPORT_DIRECTORY operator ++(PIMAGE_EXPORT_DIRECTORY a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_EXPORT_DIRECTORY(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_EXPORT_DIRECTORY(ptr);
            }
        }

        public class PWORD : ManagedPtr<ushort>
        {
            public PWORD(IntPtr address) : base(address)
            {
            }

            public PWORD(object value) : base(value)
            {
            }

            public static PWORD operator +(PWORD c1, int c2)
            {
                return new PWORD(c1.Address + c2 * c1.StructSize);
            }

            public static PWORD operator ++(PWORD a)
            {
                return a + 1;
            }

            public static explicit operator PWORD(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PWORD(ptr);
            }
        }

        public class PDWORD : ManagedPtr<uint>
        {
            public PDWORD(IntPtr address) : base(address)
            {
            }

            public PDWORD(object value) : base(value)
            {
            }

            public static PDWORD operator +(PDWORD c1, int c2)
            {
                return new PDWORD(c1.Address + c2 * c1.StructSize);
            }

            public static PDWORD operator ++(PDWORD a)
            {
                return a + 1;
            }

            public static explicit operator PDWORD(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PDWORD(ptr);
            }
        }

        public class PIMAGE_IMPORT_BY_NAME : ManagedPtr<IMAGE_IMPORT_BY_NAME>
        {
            public PIMAGE_IMPORT_BY_NAME(IntPtr address) : base(address)
            {
            }

            public PIMAGE_IMPORT_BY_NAME(object value) : base(value)
            {
            }

            public static PIMAGE_IMPORT_BY_NAME operator +(PIMAGE_IMPORT_BY_NAME c1, int c2)
            {
                return new PIMAGE_IMPORT_BY_NAME(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_IMPORT_BY_NAME operator ++(PIMAGE_IMPORT_BY_NAME a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_IMPORT_BY_NAME(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_IMPORT_BY_NAME(ptr);
            }
        }

        public class PBYTE : ManagedPtr<byte>
        {
            public PBYTE(IntPtr address) : base(address)
            {
            }

            public PBYTE(object value) : base(value)
            {
            }

            public static PBYTE operator +(PBYTE c1, int c2)
            {
                return new PBYTE(c1.Address + c2 * c1.StructSize);
            }

            public static PBYTE operator ++(PBYTE a)
            {
                return a + 1;
            }

            public static explicit operator PBYTE(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PBYTE(ptr);
            }
        }

        public class PIMAGE_BASE_RELOCATION : ManagedPtr<IMAGE_BASE_RELOCATION>
        {
            public PIMAGE_BASE_RELOCATION(IntPtr address) : base(address)
            {
            }

            public PIMAGE_BASE_RELOCATION(object value) : base(value)
            {
            }

            public static PIMAGE_BASE_RELOCATION operator +(PIMAGE_BASE_RELOCATION c1, int c2)
            {
                return new PIMAGE_BASE_RELOCATION(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_BASE_RELOCATION operator ++(PIMAGE_BASE_RELOCATION a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_BASE_RELOCATION(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_BASE_RELOCATION(ptr);
            }
        }

        public class PSHORT : ManagedPtr<short>
        {
            public PSHORT(IntPtr address) : base(address)
            {
            }

            public PSHORT(object value) : base(value)
            {
            }

            public static PSHORT operator +(PSHORT c1, int c2)
            {
                return new PSHORT(c1.Address + c2 * c1.StructSize);
            }

            public static PSHORT operator ++(PSHORT a)
            {
                return a + 1;
            }

            public static explicit operator PSHORT(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PSHORT(ptr);
            }
        }

        public class PIMAGE_TLS_DIRECTORY32 : ManagedPtr<IMAGE_TLS_DIRECTORY32>
        {
            public PIMAGE_TLS_DIRECTORY32(IntPtr address) : base(address)
            {
            }

            public PIMAGE_TLS_DIRECTORY32(object value) : base(value)
            {
            }

            public static PIMAGE_TLS_DIRECTORY32 operator +(PIMAGE_TLS_DIRECTORY32 c1, int c2)
            {
                return new PIMAGE_TLS_DIRECTORY32(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_TLS_DIRECTORY32 operator ++(PIMAGE_TLS_DIRECTORY32 a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_TLS_DIRECTORY32(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_TLS_DIRECTORY32(ptr);
            }
        }

        public class PIMAGE_LOAD_CONFIG_DIRECTORY32 : ManagedPtr<IMAGE_LOAD_CONFIG_DIRECTORY32>
        {
            public PIMAGE_LOAD_CONFIG_DIRECTORY32(IntPtr address) : base(address)
            {
            }

            public PIMAGE_LOAD_CONFIG_DIRECTORY32(object value) : base(value)
            {
            }

            public static PIMAGE_LOAD_CONFIG_DIRECTORY32 operator +(PIMAGE_LOAD_CONFIG_DIRECTORY32 c1, int c2)
            {
                return new PIMAGE_LOAD_CONFIG_DIRECTORY32(c1.Address + c2 * c1.StructSize);
            }

            public static PIMAGE_LOAD_CONFIG_DIRECTORY32 operator ++(PIMAGE_LOAD_CONFIG_DIRECTORY32 a)
            {
                return a + 1;
            }

            public static explicit operator PIMAGE_LOAD_CONFIG_DIRECTORY32(IntPtr ptr)
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                return new PIMAGE_LOAD_CONFIG_DIRECTORY32(ptr);
            }
        }
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class CPlusPlusImports
    {
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, UIntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("Dbghelp.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern IntPtr ImageRvaToVa(IntPtr NtHeaders, IntPtr Base, UIntPtr Rva, [Optional] IntPtr LastRvaSection);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessHeap();

        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        [DllImport("NTDLL.DLL", SetLastError = true)]
        public static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, IntPtr pbi, uint cb, out uint pSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize, out UIntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern void GetSystemTimeAsFileTime(out System.Runtime.InteropServices.ComTypes.FILETIME lpSystemTimeAsFileTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, out UIntPtr lpNumberOfBytesRead)
        {
            var handle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
            var result = ReadProcessMemory(hProcess, lpBaseAddress, handle.AddrOfPinnedObject(), lpBuffer.Length, out lpNumberOfBytesRead);
            handle.Free();
            return result;
        }

        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, out uint lpBuffer, out UIntPtr lpNumberOfBytesRead)
        {
            var buffer = new byte[4];
            var result = ReadProcessMemory(hProcess, lpBaseAddress, buffer, out lpNumberOfBytesRead);
            lpBuffer = BitConverter.ToUInt32(buffer, 0);
            return result;
        }

        public static bool ReadProcessMemory<T>(IntPtr hProcess, IntPtr lpBaseAddress, out T lpBuffer, out UIntPtr lpNumberOfBytesRead) where T : struct
        {
            var buffer = new byte[Marshal.SizeOf(typeof(T))];
            var result = ReadProcessMemory(hProcess, lpBaseAddress, buffer, out lpNumberOfBytesRead);
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            lpBuffer = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();

            return result;
        }

        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }
    }
}
