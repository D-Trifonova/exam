using Newtonsoft.Json;
using PeNet;
using PeNet.Header.Pe;
using System.Xml;
using Formatting = Newtonsoft.Json.Formatting;

namespace _3Kurs_Izbiraema0
{
    public class Program
    {
        // Open a PE files
        // Files larger than 10 MB
        private static void OpenPEFileWay1()
        {
            var peHeader = new PeNet.PeFile(@"C:\Windows\twain_32.dll"); // C:\Windows\System32\kernel32.dll
            Console.WriteLine("Open PE File Way 1: " + peHeader);
            Console.WriteLine("//-------------------------------");
        }
        private static void OpenPEFileWay2()
        {
            var bin = File.ReadAllBytes(@"C:\Windows\twain_32.dll"); // C:\Windows\System32\kernel32.dll
            var peHeader = new PeNet.PeFile(bin);
            Console.WriteLine("Open PE File Way 2: " + peHeader);
            Console.WriteLine("//-------------------------------");
        }

        // Can lead to unwanted side - effects!
        private static void OpenPEFileWay3()
        {
            using var fileStream = File.OpenRead(@"C:\Windows\twain_32.dll"); // C:\Windows\System32\kernel32.dll
            var peHeader = new PeNet.PeFile(fileStream);
            Console.WriteLine("Open PE File Way 3 (side-effect may occure): " + peHeader);
            Console.WriteLine("//-------------------------------");
        }

        // The fastest method for large files with the lowest memory consumption of all methods is a memory mapped file. As with the streams, all writes are on the original input file!
        private static void OpenPEFileWay4()
        {
            using var mmf = new PeNet.FileParser.MMFile(@"C:\Windows\twain_32.dll"); // C:\Windows\System32\kernel32.dll
            var peHeader = new PeNet.PeFile(mmf);
            Console.WriteLine("Open PE File Way 4: " + peHeader);
        }

        // PE file test
        //using PeNet;
        private static void PEFileTest()
        {
            var file = @"C:\Users\ж\Desktop\New Text Document (2).txt"; // C:\Windows\System32\kernel32.dll
            //Console.WriteLine("File " + file); // TEST

            // Read directly from a path to file. Uses a stream to only read the needed bytes into memory.
            var isPe1 = PeFile.IsPeFile(file);
            Console.WriteLine("Read directly from a path to file. Uses a stream to only read the needed bytes into memory: " + isPe1);

            // Use a buffer to check if the file is a PE file.
            var buff = File.ReadAllBytes(file);
            var isPe2 = PeFile.IsPeFile(buff);
            Console.WriteLine("Use a buffer to check if the file is a PE file: " + isPe2);

            // Uses a stream to check if "file" is a PE file.
            using var fs = File.OpenRead(file);
            var isPe3 = PeFile.IsPeFile(fs);
            Console.WriteLine("Uses a stream to check if \"file\" is a PE file" + isPe3);

            // Uses a memory mapped file to check if "file" is a PE file.
            using var mmf = new PeNet.FileParser.MMFile(file);
            var isPe4 = PeFile.IsPeFile(mmf);
            Console.WriteLine("Uses a memory mapped file to check if \"file\" is a PE file: " + isPe4);
        }

        // Try Parse
        //using PeNet;
        private static void TryParse()
        {
            var file = @"C:\Users\ж\Desktop\New Text Document (2).txt"; // C:\Windows\System32\kernel32.dll
            //Console.WriteLine("File " + file); // TEST

            // From file path. Uses a FileStream internally.
            var isPe1 = PeFile.TryParse(file, out var peFile);
            Console.WriteLine("From file path. Uses a FileStream internally: " + isPe1);

            // From a byte array.
            var buff = File.ReadAllBytes(file);
            var isPe2 = PeFile.TryParse(buff, out var peFile1);
            Console.WriteLine("From a byte array: " + isPe2);

            // From a stream.
            using var fs = File.OpenRead(file);
            var isPe3 = PeFile.TryParse(fs, out var peFile2);
            Console.WriteLine("From a stream: " + isPe3);

            // From a memory mapped file.
            using var mmf = new PeNet.FileParser.MMFile(file);
            var isPe4 = PeFile.TryParse(mmf, out var peFile3);
            Console.WriteLine("From a memory mapped file: " + isPe4);
        }

        // Import Hash
        private static void ImportHash()
        {
            var peHeader = new PeNet.PeFile(@"C:\Users\ж\Desktop\New Text Document (2).txt"); // C:\Windows\System32\kernel32.dll

            var ih = peHeader.ImpHash;
            Console.WriteLine("Import Hash: " + ih);
        }

        // TypeRefHash
        private static void TypeRefHash()
        {
            var file = @"C:\Users\ж\Desktop\New Text Document (2).txt"; // C:\Windows\System32\kernel32.dll

            var peFile = new PeFile(file);

            // get the TRH as a hex-string.
            var trh = peFile.TypeRefHash;

            Console.WriteLine("TypeRefHash: " + trh);
            // prints for example the TRH:
            // > d633db771449e2c37e1689a8c291a4f4646ce156652a9dad5f67394c0d92a8c4
        }

        // File Hashes
        private static void MD5()
        {
            var pe = new PeNet.PeFile(@"c:\windows\system32\calc.exe"); // Calculator
            Console.WriteLine($"MD5: {pe.Md5}");
        }
        private static void SHA1()
        {
            var pe = new PeNet.PeFile(@"c:\windows\system32\calc.exe");
            Console.WriteLine($"SHA-1: {pe.Sha1}");
        }
        private static void Sha256()
        {
            var pe = new PeNet.PeFile(@"c:\windows\system32\calc.exe");
            Console.WriteLine($"SHA256: {pe.Sha256}");
        }

        // Export Data: As String
        private static void PrintWholePEAsString()
        {
            var pefile = new PeNet.PeFile(@"C:\Users\ж\Desktop\New Text Document (2).txt"); // c:\windows\system32\kernel32.dll
            Console.WriteLine("Export Data: As String: " + pefile);
        }
        private static void PrintSpecificStructureAsString()
        {
            var pefile = new PeNet.PeFile(@"C:\Users\ж\Desktop\New Text Document (2).txt"); // c:\windows\system32\kernel32.dll
            Console.WriteLine("Prints Specific Structure As String: " + pefile.ImageResourceDirectory);
        }

        // As JSON
        //using Newtonsoft.Json;
        private static void FormattedJSONString() // JSON json
        {
            var pefile = new PeNet.PeFile(@"C:\Users\ж\Desktop\New Text Document (2).txt"); // c:\windows\system32\kernel32.dll
            JsonConvert.SerializeObject(pefile.ImageResourceDirectory, Formatting.Indented);
            //Console.WriteLine(json);

            //Console.WriteLine();

            Console.WriteLine("Export Data: As JSON: " + pefile);
        }

        // Sections: Access sections
        private static void AccsessSections()
        {
            var peFile = new PeFile("myapp.exe");

            // Get array with all section table entries.
            var sections = peFile.ImageSectionHeaders;
            Console.WriteLine("Get array with all section table entries: " + sections);
        }

        // Add section
        private static void AddSection()
        {
            var peFile = new PeFile("myapp.exe");

            // Add a new section with the name ".name", the size 100 and section characteristics.
            // Section names have a max. length of 8 characters.
            peFile.AddSection(".name", 100, (ScnCharacteristicsType)0x40000040);
        }

        // Remove section
        private static void RemoveSection()
        {
            var peFile = new PeFile("myapp.exe");

            // Remove the resource section from the section table and the content of the section from the file.
            peFile.RemoveSection(".rsrc");

            // Alternatively you can only remove the section from the section table and keep the content of the section in the file.
            peFile.RemoveSection(".rsrc", false);
        }

        // Imports: Access Import Descriptors
        private static void AccessImportDescriptors()
        {
            var peFile = new PeFile("myapp.exe");

            var idescs = peFile.ImageImportDescriptors;
            var bdescs = peFile.ImageBoundImportDescriptor;
            var ddescs = peFile.ImageDelayImportDescriptor;

            Console.WriteLine(idescs);
            Console.WriteLine(bdescs);
            Console.WriteLine(ddescs);
        }

        // Access imported Functions
        private static void AccessImportedFunctions()
        {
            var peFile = new PeFile("myapp.exe");

            // Print all imported modules with their corresponding functions.
            foreach (var imp in peFile.ImportedFunctions)
            {
                Console.WriteLine($"Print all imported modules with their corresponding functions: {imp.DLL} - {imp.Name} - {imp.Hint} - {imp.IATOffset}");
            }
        }

        // Add Imports
        // One Import
        private static void AddOneImport()
        {
            var peFile = new PeFile("myapp.exe");
            peFile.AddImport("gdi32.dll", "StartPage");
        }

        // Multiple Imports
        private static void AddMultipleImports()
        {
            var peFile = new PeFile("myapp.exe");

            var ai1 = new AdditionalImport("gdi32.dll", new List<string> { "StartPage" });
            var ai2 = new AdditionalImport("ADVAPI32.dll", new List<string> { "RegCloseKey" });
            var importList = new List<AdditionalImport> { ai1, ai2 };

            peFile.AddImports(importList);
        }
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();
            app.MapGet("/", () => "");

            // PDB & Debug Information
            var peFile = new PeFile("peWithDbgInfo.exe");

            // Select the first debug directory with
            // PDB information available.
            var pdbInfo = peFile
                .ImageDebugDirectory
                .First(idb => idb.CvInfoPdb70 != null)
                .CvInfoPdb70;

            // Print content of the Code View PDB v7 structure
            Console.WriteLine(pdbInfo);

            /*Output:
                CvInfoPdb70
                CvSignature: 1396986706
                Signature: 6dec1348-e330-45a1-b761-a6a5951a38c0
                Age: 1
                PdbFileName:  D:\a\_work\1\s\artifacts\obj\win-x64.Release\corehost\apphost\standalone\apphost.pdb*/

            Console.WriteLine();

            byte choise;
            Console.Write("Choose from the menu1: ");
            Console.WriteLine("0. Exit");
            Console.WriteLine("1. Open a PE files");
            Console.WriteLine("2. PE file test");
            Console.WriteLine("3. Try Parse");
            Console.WriteLine("4. Import Hash");
            Console.WriteLine("5. TypeRefHash");
            Console.WriteLine("6. File Hashes");
            Console.WriteLine("7. Export Data");
            Console.WriteLine("8. Access sections");
            Console.WriteLine("9. Add section");
            Console.WriteLine("10. Remove section");
            Console.WriteLine("11. Access Import Descriptors");
            Console.WriteLine("12. Access imported Functions");
            Console.WriteLine("13. Add Imports");
            choise = byte.Parse(Console.ReadLine());

            while (true)
            {
                if (choise == 0)
                {
                    break;
                }
                else if (choise == 1)
                {
                    OpenPEFileWay1();
                    OpenPEFileWay2();
                    OpenPEFileWay3();
                    OpenPEFileWay4();
                    choise = byte.Parse(Console.ReadLine());
                }
                else if (choise == 2)
                {
                    PEFileTest();
                }
                else if (choise == 3)
                {
                    TryParse();
                }
                else if (choise == 4)
                {
                    ImportHash();
                    return;
                }
                else if (choise == 5)
                {
                    TypeRefHash();
                    return;
                }
                else if (choise == 6)
                {
                    MD5();
                    SHA1();
                    Sha256();
                    return;
                }
                else if (choise == 7)
                {
                    PrintWholePEAsString();
                    PrintSpecificStructureAsString();
                    FormattedJSONString();
                    return;
                }
                else if (choise == 8)
                {
                    AccsessSections();
                    return;
                }
                else if (choise == 9)
                {
                    AddSection();
                }
                else if (choise == 10)
                {
                    RemoveSection();
                }
                else if (choise == 11)
                {
                    AccessImportDescriptors();
                    return;
                }
                else if (choise == 12)
                {
                    AccessImportedFunctions();
                    return;
                }
                else if (choise == 13)
                {
                    Console.WriteLine("One Import");
                    AddOneImport();
                    Console.WriteLine("Multiple Imports");
                    AddMultipleImports();
                    return;
                }
                else
                {
                    throw new Exception("Try again");
                }
            }

            app.Run();

            // ------------------------------------------------------------------------------------------------------------------------------------

            //var builder = WebApplication.CreateBuilder(args);
            //var app = builder.Build();

            //app.MapGet("/", () => "Hello World!");

            //app.Run();
        }
    }
}

/* As JSON
 Output:
{
  "DirectoryEntries": [
    {
      "ResourceDirectory": {
        "DirectoryEntries": [
          {
            "ResourceDirectory": {
              "DirectoryEntries": [
                {
                  "ResourceDirectory": null,
                  "ResourceDataEntry": {
                    "OffsetToData": 726104,
                    "Size1": 200,
                    "CodePage": 0,
                    "Reserved": 0
                  },
                  "Name": 1033,
                  "ResolvedName": "unknown",
                  "ID": 1033,
                  "OffsetToData": 128,
                  "OffsetToDirectory": 128,
                  "DataIsDirectory": false,
                  "IsNamedEntry": false,
                  "IsIdEntry": true
                }
              ],
              "Characteristics": 0,
              "TimeDateStamp": 0,
              "MajorVersion": 0,
              "MinorVersion": 0,
              "NumberOfNameEntries": 0,
              "NumberOfIdEntries": 1
            },
            "ResourceDataEntry": null,
            "Name": 1,
            "ResolvedName": "Cursor",
            "ID": 1,
            "OffsetToData": 2147483728,
            "OffsetToDirectory": 80,
            "DataIsDirectory": true,
            "IsNamedEntry": false,
            "IsIdEntry": true
          }
        ],
        "Characteristics": 0,
        "TimeDateStamp": 0,
        "MajorVersion": 0,
        "MinorVersion": 0,
        "NumberOfNameEntries": 0,
        "NumberOfIdEntries": 1
      },
      "ResourceDataEntry": null,
      "Name": 2147483808,
      "ResolvedName": "MUI",
      "ID": 160,
      "OffsetToData": 2147483680,
      "OffsetToDirectory": 32,
      "DataIsDirectory": true,
      "IsNamedEntry": true,
      "IsIdEntry": false
    },
    {
      "ResourceDirectory": {
        "DirectoryEntries": [
          {
            "ResourceDirectory": {
              "DirectoryEntries": [
                {
                  "ResourceDirectory": null,
                  "ResourceDataEntry": {
                    "OffsetToData": 725168,
                    "Size1": 932,
                    "CodePage": 0,
                    "Reserved": 0
                  },
                  "Name": 1033,
                  "ResolvedName": "unknown",
                  "ID": 1033,
                  "OffsetToData": 144,
                  "OffsetToDirectory": 144,
                  "DataIsDirectory": false,
                  "IsNamedEntry": false,
                  "IsIdEntry": true
                }
              ],
              "Characteristics": 0,
              "TimeDateStamp": 0,
              "MajorVersion": 0,
              "MinorVersion": 0,
              "NumberOfNameEntries": 0,
              "NumberOfIdEntries": 1
            },
            "ResourceDataEntry": null,
            "Name": 1,
            "ResolvedName": "Cursor",
            "ID": 1,
            "OffsetToData": 2147483752,
            "OffsetToDirectory": 104,
            "DataIsDirectory": true,
            "IsNamedEntry": false,
            "IsIdEntry": true
          }
        ],
        "Characteristics": 0,
        "TimeDateStamp": 0,
        "MajorVersion": 0,
        "MinorVersion": 0,
        "NumberOfNameEntries": 0,
        "NumberOfIdEntries": 1
      },
      "ResourceDataEntry": null,
      "Name": 16,
      "ResolvedName": "Version",
      "ID": 16,
      "OffsetToData": 2147483704,
      "OffsetToDirectory": 56,
      "DataIsDirectory": true,
      "IsNamedEntry": false,
      "IsIdEntry": true
    }
  ],
  "Characteristics": 0,
  "TimeDateStamp": 0,
  "MajorVersion": 0,
  "MinorVersion": 0,
  "NumberOfNameEntries": 1,
  "NumberOfIdEntries": 1
}*/