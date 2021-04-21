using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Net;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Threading;
using Inspector;
using MainLogic;


namespace ITHC
{
    class ITCMain
    {
        static string _toolDirectory = null;

        [STAThread]
        static void Main(string[] args)
        {
            DateTime startTime;
            string main_action = "";
            int argument_index = 0;

            _toolDirectory = System.IO.Directory.GetCurrentDirectory();

            // Display banner
            Console.WriteLine("[*] -= Inspector Test Harness Client v1.1, Copyright 2007-2009 HBGary, INC  =-");

            if (args.Length == 0 || (args[0].Equals("/?") == true || args[0].ToLower().StartsWith("-h") == true) || args.Length < 2)
            {
                Console.WriteLine("[*] HELP [*]");

                Console.WriteLine("    Usage: ITHC.exe <project_path> <action> <parameters> \n");

                // Print known actions
                Console.WriteLine("    ACTIONS:");
                Console.WriteLine("    -As      Run the WPMA analyzer against the input file");
                Console.WriteLine("             format: ITHC.exe <project_path> -As <input_image_path>");
                Console.WriteLine("    -AsDDNA  Run the WPMA analyzer against the input file and output a textfile with DDNA info");
                Console.WriteLine("             format: ITHC.exe <project_path> -AsDDNA <input_image_path>");
                Console.WriteLine("    -Dp      Dump the contents of the project to the console");
                Console.WriteLine("             format: ITHC.exe <project_path> -Dp");
                Console.WriteLine("    -Del     Delete the specified project. Use -f to avoid the yes/no prompt");
                Console.WriteLine("             format: ITHC.exe <project_path> -Del [-f]");
                Console.WriteLine("    -Ex      Extract and analyze the specified module.");
                Console.WriteLine("             format: ITHC.exe <project_path> -Ex <module> <process>");
                return;
            }

            // mark the start time
            startTime = DateTime.Now;

            // Main THC operation
            string project_path = "";
            string analyzer_name = "";
            string input_file_path = "";

            main_action = args[(argument_index + 1)];
            switch (main_action)
            {
                // Analyze File
                case "-As":
                    if (args.Length != 3)
                    {
                        Console.WriteLine("[!] Incorrect number of arguments. Exiting...");
                        break;
                    }
                    // Get the project name argument
                    project_path = args[(argument_index + 0)];
                    // Analyzer name
                    analyzer_name = "Analyzer_WPMA.dll";
                    // File Path
                    input_file_path = args[(argument_index + 2)];

                    Console.WriteLine("[*] Analyzing single file into project...");
                    if (THCAnalyzeFile(project_path,
                                        analyzer_name,
                                        input_file_path,
                                        false))
                    {
                        Console.WriteLine("[+] File successfully analyzed.");
                    }
                    else
                    {
                        Console.WriteLine("[E] analysis failed!");
                    }
                    break;
                // Analyze File and output DDNA text file
                case "-AsDDNA":
                    if (args.Length != 3)
                    {
                        Console.WriteLine("[!] Incorrect number of arguments. Exiting...");
                        break;
                    }

                    // Get the project name argument
                    project_path = args[(argument_index + 0)];
                    // Analyzer name
                    analyzer_name = "Analyzer_WPMA.dll";
                    // File Path
                    input_file_path = args[(argument_index + 2)];

                    Console.WriteLine("[*] Analyzing single file into project with DDNA information...");
                    if (THCAnalyzeFile(project_path,
                                        analyzer_name,
                                        input_file_path,
                                        true))
                    {
                        Console.WriteLine("[+] File successfully analyzed.");
                    }
                    else
                    {
                        Console.WriteLine("[E] analysis failed!");
                    }
                    break;
                // Dump project contents
                case "-Dp":
                    // Get the project name argument
                    project_path = args[(argument_index + 0)];

                    Console.WriteLine("[*] Dumping project contents to console...");
                    if (THCDumpProject(project_path) == true)
                    {
                        Console.WriteLine("[+] Project successfully dumped.");
                    }
                    else
                    {
                        Console.WriteLine("[E] dump failed!");
                    }
                    break;
                case "-Ex":
                    // extract and analyze specific binaries here

                    project_path = args[(argument_index + 0)];
                    string module = args[(argument_index + 2)];
                    string process = args[(argument_index + 3)];

                    Console.WriteLine("[+] Extracting and analyzing specified module");
                    if (THCAnalyzeModule(project_path, module, process))
                    {
                        Console.WriteLine("[+] Module successfully analyzed");
                    }
                    else
                    {
                        Console.WriteLine("[E] Module analysis failed!");
                    }

                    break;
                case "-Del":
                    //delete the project specified

                    project_path = args[(argument_index + 0)];
                    string project_directory = project_path.Substring(0, project_path.LastIndexOf("\\"));

                    if (args.Length == 3 && args[(argument_index + 2)] == "-f")
                    {
                        //Delete everything in the project's folder
                        Console.WriteLine("[+] Deleting project...");
                        Directory.Delete(project_directory, true);
                        Console.WriteLine("[+] Project deleted.");
                    }
                    else
                    {
                        Console.WriteLine("[?] Are you sure you want to delete this project? (Y/N)");
                        string choice = Console.ReadLine();
                        choice = choice.ToLower();

                        if (choice.Length <= 3 && choice.Contains("y"))
                        {
                            //Delete everything in the project's folder
                            Console.WriteLine("[+] Deleting project...");
                            Directory.Delete(project_directory, true);
                            Console.WriteLine("[+] Project deleted.");
                        }
                    }

                    break;
                default:
                    Console.WriteLine("[!] Unknown action. Please try again");
                    break;
            }

            Console.WriteLine("[*] Goodbye ...\n");
            Console.WriteLine("[TOTAL_TIME] {0}", DateTime.Now.Subtract(startTime));
            return;
        }

        // this function will read in a new file and create or import it into the project via the given analyzer
        static bool THCAnalyzeFile(string project_path, string analyzer_name, string file_path, bool DDNAWeight)
        {
            // Remove the old temp file in case that this project already exists
            string tempfile = file_path + ".tmp";
            if (File.Exists(tempfile))
            {
                File.Delete(tempfile);
            }

            IProject theProject = null;
            IBinaryAnalyzer theAnalyzer = null;

            try
            {
                Inspector.EventManager.BeginBulkUpdate();

                if (File.Exists(project_path))
                {
                    theProject = OpenProject(project_path);
                }
                else
                {
                    theProject = NewProject(project_path);
                }

                if (theProject == null)
                {
                    Console.WriteLine("[E]Project file could not be created or opened.");
                    Console.WriteLine("   This is probably due to the HASP key not being inserted.");
                    Console.WriteLine("   Please insert your HASP key and try again.");
                    Inspector.EventManager.EndBulkUpdate();
                    return (false);
                }

                string aPackageName = file_path.TrimEnd(new char[] { '\\', '/' });
                int last = file_path.LastIndexOfAny(new char[] { '\\', '/' });

                aPackageName = aPackageName.Substring(last);
                aPackageName = aPackageName.TrimStart(new char[] { '\\', '/' });

                // Print header
                Console.WriteLine("[*] Analyzer: \"" + analyzer_name + "\" File: \"" + file_path + "\"");

                // run analyzer
                try
                {
                    // create the case to attach the project to
                    IPackage aParentSystemPackage = PackageFactory.Create(theProject.DataStore);
                    Guid newCaseID = aParentSystemPackage.ID;

                    // Set up information about the case. This is left blank in the example but can be filled in if needed
                    aParentSystemPackage.Name = "Case 001";
                    aParentSystemPackage.BaseVirtualAddress = 0;
                    aParentSystemPackage.EntryPointOffset = 0;
                    aParentSystemPackage.ImageLength = 0;
                    theProject.DataStore.SetNamedAttribute(DataGroup.Package, aParentSystemPackage.ID, "sAnalystName", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Package, aParentSystemPackage.ID, "sCaseNumber", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Package, aParentSystemPackage.ID, "sCaseDescription", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Package, aParentSystemPackage.ID, "sCaseDate", DateTime.Now.ToShortDateString());
                    theProject.DataStore.SetNamedAttribute(DataGroup.Package, aParentSystemPackage.ID, "sCaseTime", DateTime.Now.ToShortTimeString());
                    theProject.DataStore.SetNamedAttribute(DataGroup.Package, aParentSystemPackage.ID, "sCaseLocation", string.Empty);

                    IClass aPhysicalMemoryClass = ClassFactory.Create(theProject.DataStore, aParentSystemPackage.ID);
                    aPhysicalMemoryClass.Name = "Physical Memory Snapshot";

                    IClass aReportClass = ClassFactory.Create(theProject.DataStore, aParentSystemPackage.ID);
                    aReportClass.Name = "Report";

                    // Set up the analyzer
                    theAnalyzer = BuildAnalyzer(analyzer_name, theProject);
                    if (null == theAnalyzer)
                    {
                        Console.WriteLine("[E] Analyzer could not be built.");
                        Inspector.EventManager.EndBulkUpdate();
                        return false;
                    }

                    // register progress callback, show progress bar
                    theAnalyzer.StatusUpdateEvent += new StatusUpdateHandler(THC_StatusUpdateEvent);

                    // First we initialize the package and the snapshot
                    IPackage aNewPackage = Inspector.PackageFactory.Create(theProject.DataStore);
                    ISnapshot aNewSnapshot = Inspector.SnapshotFactory.Create(theProject.DataStore, aNewPackage.ID);
                    if (null == aNewPackage)
                    {
                        Console.WriteLine("[E] Error, could not create package.");
                        Inspector.EventManager.EndBulkUpdate();
                        return (false);
                    }

                    aNewPackage.Name = aPackageName;
                    aNewPackage.BaseVirtualAddress = 0;
                    aNewPackage.EntryPointOffset = 0;
                    aNewPackage.ImageLength = 0;

                    aNewSnapshot.ReferenceFileName = file_path;
                    theProject.DataStore.SetNamedAttribute(DataGroup.Snapshot, aNewSnapshot.ID, "sMachineName", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Snapshot, aNewSnapshot.ID, "sMachineLocation", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Snapshot, aNewSnapshot.ID, "sSnapshotDescription", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Snapshot, aNewSnapshot.ID, "sSnapshotBackground", string.Empty);
                    theProject.DataStore.SetNamedAttribute(DataGroup.Snapshot, aNewSnapshot.ID, "sSnapshotDate", DateTime.Now.ToShortDateString());
                    theProject.DataStore.SetNamedAttribute(DataGroup.Snapshot, aNewSnapshot.ID, "sSnapshotTime", DateTime.Now.ToShortTimeString());
                    aNewPackage.InitialSnapshot = aNewSnapshot;

                    // the package needs to be placed under the correct node in the schema
                    // the user should have an active case file for this binary
                    // the binary MAY be under any node, however.  This should be passed in.
                    IPackage aCasePackage = PackageFactory.Open(theProject.DataStore, aParentSystemPackage.ID);
                    System.Diagnostics.Debug.Assert(null != aCasePackage, "case package not found");
                    aNewPackage.ParentPackage = aCasePackage;

                    // Check if this was a static import
                    foreach (IClass aClass in aCasePackage.ClassList)
                    {
                        if (aClass.Name == "Physical Memory Snapshot")
                        {
                            aNewPackage.ParentClass = aClass;

                            break;
                        }
                    }

                    // Analyze the file and initialize the package
                    if (false == theAnalyzer.Analyze(aNewPackage, 0, false))
                    {
                        // incomplete analysis.
                        Console.WriteLine("[E] There was an error during physical memory analysis.  The analysis may be incomplete. This is usually due to a corrupt or unknown memory image type.");

                        // make sure ImageLength is still set so the binary hex editor still works
                        if (null != aNewPackage.InitialSnapshot)
                        {
                            aNewPackage.ImageLength = aNewPackage.InitialSnapshot.Length;
                        }
                    }

                    aNewPackage.AddAnalysisHistoryStep("WPMA");

                    // Some status information
                    Console.WriteLine("[*] Analysis complete on file \"" + file_path + "\"");
                    Console.WriteLine("[*] Synchronizing disassembly data to Inspector server...");

                    // now save the project
                    SaveProject(theProject);


                    // Analysis of DDNA weights
                    if (DDNAWeight)
                    {
                        Console.WriteLine("[*] Writing DDNA results to output file...");
                        ArrayList allReportItems = theProject.WorkItems;
                        foreach (IWorkObject wo in allReportItems)
                        {
                            object oRuleType = theProject.DataStore.GetNamedAttribute(DataGroup.WorkItem, wo.ID, "sRuleType");
                            if (null != oRuleType)
                            {
                                if ((string)oRuleType == "DDNA")
                                {
                                    IWorkObject aBookmark = WorkFactory.Open(theProject.DataStore, wo.ID);
                                    THCAnalyzeDDNAWeight(wo, theProject, file_path);
                                }
                            }
                        }
                    }

                    Console.WriteLine("[*] Done!");
                }
                catch (ArgumentException e)
                {
                    Console.WriteLine("failed to analyze specified file: " + e.Message);
                    Inspector.EventManager.EndBulkUpdate();
                    return (false);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Inspector.EventManager.EndBulkUpdate();
                return (false);
            }

            Inspector.EventManager.EndBulkUpdate();

            return (true);
        }

        // This function searches for the module specified on the command line and analyzes it.
        static bool THCAnalyzeModule(string project_path, string module_name, string process_name)
        {
            IProject theProject = null;

            if (File.Exists(project_path))
            {
                theProject = OpenProject(project_path);
            }

            if (theProject == null)
            {
                Console.WriteLine("[E] Project file could not be opened.");
                return false;
            }

            bool ableToAnalyze = false;

            foreach (IPackage aPackage in theProject.PackageList)
            {
                if (aPackage.Name.ToLower() == module_name.ToLower() && aPackage.ParentPackage.Name.ToLower() == process_name.ToLower())
                {
                    //Extract and analyze the module
                    if (AnalyzePackage(aPackage.ID, theProject.DataStore, theProject, theProject.DataStore.RootPath))
                    {
                        ableToAnalyze = true;
                    }
                }
            }
            return ableToAnalyze;
        }

        //The following creates an text file with weight info from DDNA strings
        static bool THCAnalyzeDDNAWeight(IWorkObject wo, IProject theProject, string image)
        {
            string DDNA = wo.Report;
            string Module = "Unknown";
            string Process = "Unknown";
        
            string Weight = "";
            StreamWriter sw = null;
            

            //Checking if an output file already exists and sets up streams to either create or append to 
            //the output file
            if (!File.Exists(theProject.DataStore.StorePath + "\\" + "DDNA" + theProject.DataStore.StoreName + ".txt"))
            {
                //Opens or creates the output file with weight information
                Stream WeightFile = new FileStream(theProject.DataStore.StorePath + "\\" + "DDNA" + theProject.DataStore.StoreName + ".txt",
                    FileMode.OpenOrCreate, FileAccess.Write, FileShare.Write);

                sw = new StreamWriter(WeightFile);
                //The first line is the name of the image
                //sw.WriteLine(image);
            }
            else
            {
                sw = File.AppendText(theProject.DataStore.StorePath + "\\" + "DDNA" + theProject.DataStore.StoreName + ".txt");
            }

            IWorkObject aBookmark = WorkFactory.Open(theProject.DataStore, wo.ID);
            System.Diagnostics.Debug.Assert(null != aBookmark);

            // see if we can determine the parent module
            if (Guid.Empty != aBookmark.ReferenceObjectID)
            {
                UInt32 objectType = (UInt32)theProject.DataStore.GetNamedValue(DataGroup.GenericObject, aBookmark.ReferenceObjectID, DataValueName.GroupName);
                IPackage targetModule = null;

                switch (objectType)
                {
                    case (UInt32)DataGroup.Package:
                        targetModule = PackageFactory.Open(theProject.DataStore, aBookmark.ReferenceObjectID);
                        break;
                    case (UInt32)DataGroup.DataInstance:
                    case (UInt32)DataGroup.Block:
                        {
                            Guid parentID = (Guid)theProject.DataStore.GetNamedValue(DataGroup.GenericObject, aBookmark.ReferenceObjectID, DataValueName.ParentID);
                            targetModule = PackageFactory.Open(theProject.DataStore, parentID);
                        }                        
                        break;                   
                }

                if (null != targetModule)
                {
                    Module = targetModule.Name;
                    Process = targetModule.ParentProcessName;
                }
            }
            else
            {
                Module = "Unknown";
            }

            Weight = (string)theProject.DataStore.GetNamedAttribute(DataGroup.GenericObject, wo.ID, "sDDNAWeight");

                        
            //Write out the name and the DDNA string to the file
            //sw.WriteLine(Module);
            //sw.WriteLine(DDNA);

            

            //Write out the final weight for the module to the file
            //sw.WriteLine(Weight);
            sw.WriteLine(theProject.DataStore.StoreName + "," + Module + "," + Process + "," + DDNA + "," + Weight);
            //sw.WriteLine(theProject.DataStore.StoreName + "," + Module + "," + DDNA + "," + Weight);

            sw.Close();

            return true;
        }

        // This function dumps the contents of the project to the console
        static bool THCDumpProject(string project_path)
        {
            IProject theProject = null;
            try
            {
                if (File.Exists(project_path))
                {
                    theProject = OpenProject(project_path);
                }

                if (theProject == null)
                {
                    Console.WriteLine("Project file could not be opened.");
                    return (false);
                }
                try
                {
                    Console.WriteLine("Project name: " + theProject.Name);
                    Console.WriteLine("Number of packages: " + theProject.PackageList.Count);
                    foreach (IPackage aPackage in theProject.PackageList)
                    {
                        Console.WriteLine("Package: " + aPackage.Name);
                        if (aPackage.ParentPackage != null)
                        {
                            Console.WriteLine("Parent Package: " + aPackage.ParentPackage.Name);
                        }
                        Console.WriteLine("Length: " + aPackage.ImageLength.ToString("D") + " bytes.");
                        foreach (IClass aClass in aPackage.ClassList)
                        {
                            Console.WriteLine("    Class: " + aClass.Name);
                            foreach (IFunction aFunction in aClass.FunctionList)
                            {
                                Console.WriteLine("        Function: " + aFunction.Name);
                                foreach (IBlock aBlock in aFunction.BlockList)
                                {
                                    Console.WriteLine("        " + aBlock.Name + ":");
                                    foreach (IInstruction asm in aBlock.InstructionList)
                                    {
                                        Console.WriteLine(asm.VirtualAddress.ToString("X8") + "        " + asm.DisassemblyText);
                                    }
                                }
                            }
                        }
                        Console.WriteLine("Strings:");
                        foreach (InspectorDataInstance st in aPackage.Strings)
                        {
                            Console.WriteLine(st.Name);
                        }
                    }

                    Console.WriteLine("[*] Done!");
                }
                catch (ArgumentException e)
                {
                    Console.WriteLine("failed to analyze specified file: " + e.Message);
                    return (false);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return (false);
            }

            return (true);
        }

        // Extracts the package and gets it ready for analysis
        static bool AnalyzePackage(Guid thePackageID, IDataStore store, IProject theProject, string root_path)
        {
            IPackage aPackage = PackageFactory.Open(store, thePackageID);
            if (null != aPackage)
            {
                try
                {
                    Inspector.EventManager.BeginBulkUpdate();

                    // do we have a snapshot?
                    if (null == aPackage.InitialSnapshot)
                    {
                        if (null != aPackage.ParentClass && aPackage.ParentClass.Name == "Drivers")
                        {
                            // its a physical memory snapshot, try to extract it.
                            IPackage physicalMemoryPackage = aPackage.ParentPackage;
                            System.Diagnostics.Debug.Assert(null != physicalMemoryPackage);
                            ExtractPEImageFromMemory(physicalMemoryPackage, aPackage, theProject);
                        }
                        else if (null != aPackage.ParentClass && aPackage.ParentClass.Name == "Modules")
                        {
                            System.Diagnostics.Debug.Assert(null != aPackage.ParentPackage.ParentPackage);

                            IPackage physicalMemoryPackage = aPackage.ParentPackage.ParentPackage;
                            System.Diagnostics.Debug.Assert(null != physicalMemoryPackage);
                            ExtractPEImageFromMemory(physicalMemoryPackage, aPackage, theProject);
                        }
                    }

                    if (null != aPackage.InitialSnapshot)
                    {
                        if (!AnalyzePackageStrings(aPackage, root_path, theProject))
                        {
                            // If analysis fails, handle it somehow
                            // In this example we'll throw an exception that is picked up below
                            throw (new Exception("Package analysis failed"));
                        }

                        IPackage physicalMemoryPackage = aPackage.ParentPackage;
                        System.Diagnostics.Debug.Assert(null != physicalMemoryPackage);
                    }
                    else
                    {
                        Console.WriteLine("[E] No binary available, cannot analyze " + aPackage.Name);
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine("[E] Exception while analyzing snapshot: " + ex.Message);
                    return false;
                }

                SaveProject(theProject);

                if (null != aPackage)
                {
                    Inspector.EventManager.EndBulkUpdate();
                }

                return true;
            }
            return false;
        }

        // After a package is extracted then it can be analyzed here
        static bool AnalyzePackageStrings(IPackage thePackage, string root_path, IProject theProject)
        {
            try
            {
                InspectorLoader loader = new InspectorLoader(theProject.DataStore.RootPath);
                IBinaryAnalyzer bap = loader.BuildAnalyzer("Analyzer_PE.dll", theProject);
                IBinaryAnalyzer sf = loader.BuildAnalyzer("Analyzer_StringFinder.dll", theProject);

                if (thePackage.BaseVirtualAddress > 0x00000000FFFFFFFF)
                {
                    // 64 bit binary, we cannot analyze this.
                    thePackage.AddAnalysisHistoryStep("PE Analysis Failed");
                }
                else
                {
                    // set the type of the disassembler and analyzer
                    thePackage.DisassemblerName = "Disassembler_IA32.dll";
                    thePackage.AnalyzerName = "Analyzer_PE.dll";

                    if (bap != null && string.Empty != thePackage.DisassemblerName)
                    {
                        IDisassembler currentDisassembler = loader.BuildDisassembler(thePackage.DisassemblerName);
                        bap.SetDisassembler(currentDisassembler);
                    }

                    if (false == bap.Analyze(thePackage, 0, true))
                    {
                        thePackage.AddAnalysisHistoryStep("PE Analysis Failed");
                    }
                    else
                    {
                        thePackage.AddAnalysisHistoryStep("PE");
                    }
                }

                if (false == sf.Analyze(thePackage, 0, true))
                {
                    thePackage.AddAnalysisHistoryStep("Strings Analysis Failed");
                }
                else
                {
                    thePackage.AddAnalysisHistoryStep("STRINGS");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[E] Exception while analyzing binary: " + ex.Message);
                return false;
            }
            return true;
        }

        // This will extract a PE formatted executable, EXE DLL or SYS file from physical memory
        // and save it to the local filesystem so that the user may import the file into the
        // reverse engineering tool of their choice.
        static void ExtractPEImageFromMemory(
                            IPackage thePhysicalMemorySnapshot,
                            IPackage theExtractedModule,
                            IProject theProject)
        {
            IBinaryAnalyzer anAnalyzer = BuildAnalyzer("Analyzer_WPMA.dll", theProject);

            // random name to store extracted binary
            Random r = new Random();
            string random_string = r.Next().ToString();
            string theSaveFilename = theExtractedModule.Name + "." + random_string + ".livebin";

            if (false == File.Exists(thePhysicalMemorySnapshot.InitialSnapshot.ReferenceFilePath + ".tmp"))
            {
                // We cannot extract anything without doing a complete analysis over again, somehow the tmp file
                // got deleted.  We _could_ re-import from scratch again but we don't have appropriate progress-bar steps
                // for that here.
                Console.WriteLine("[E] Missing memory snapshot .tmp file. Analysis may not be complete.");
                return;
            }

            Inspector.ISnapshot extractedSnapshot =
                anAnalyzer.Extract(theSaveFilename,
                                   Inspector.BinaryExtractionType.PE_Executable_Image,
                                   thePhysicalMemorySnapshot,
                                   theExtractedModule.ID);

            if (null == extractedSnapshot)
            {
                return;
            }

            string theNewFileName = string.Empty;
            string theNewFilePath = theProject.DataStore.StorePath;

            // check the snapshot name to see if the image was mapped or unmapped, rename the file appropriately
            if (extractedSnapshot.Name == "unmapped")
            {
                theNewFileName = theExtractedModule.Name + "." + random_string + ".unmapped.livebin";
                try
                {
                    System.IO.File.Move(extractedSnapshot.ReferenceFilePath, theNewFilePath + "\\" + theNewFileName);
                }
                catch
                {
                    // Failed to move, don't update the snapshot file
                    theNewFileName = theSaveFilename;
                }
                extractedSnapshot.ReferenceFileName = theNewFileName;
            }
            else if (extractedSnapshot.Name == "mapped")
            {
                theNewFileName = theExtractedModule.Name + "." + random_string + ".mapped.livebin";
                try
                {
                    System.IO.File.Move(extractedSnapshot.ReferenceFilePath, theNewFilePath + "\\" + theNewFileName);
                }
                catch
                {
                    // Failed to move, don't update the snapshot file
                    theNewFileName = theSaveFilename;
                }
                extractedSnapshot.ReferenceFileName = theNewFileName;
            }

            // the snapshot is already stored to disk, so we don't need to store it again                     
            theExtractedModule.InitialSnapshot = extractedSnapshot;
            System.IO.FileInfo fi = new System.IO.FileInfo(extractedSnapshot.ReferenceFilePath);
            theExtractedModule.ImageLength = (uint)fi.Length;
        }

        static private void THC_StatusUpdateEvent(object sender, StatusUpdateEventArgs mve)
        {
            int Maximum = mve.Max;
            if (mve.Complete > mve.Max)
                Maximum = mve.Complete;
            Console.WriteLine(("[" + mve.Complete + " of " + mve.Max + "] \"" + mve.StatusText + "\""));
        }

        // this function creates a new project file and associates it with the returned IProject
        static IProject NewProject(string theProjectPath)
        {
            string storePath = theProjectPath.Substring(0, theProjectPath.LastIndexOf("\\"));
            string rootPath = storePath.Substring(0, storePath.LastIndexOf("\\"));
            string projectName = theProjectPath.Substring(theProjectPath.LastIndexOf("\\") + 1);
            projectName = projectName.Substring(0, projectName.LastIndexOf("."));

            // make sure we create the directory
            if (!Directory.Exists(storePath))
            {
                Directory.CreateDirectory(storePath);
            }

            if (System.IO.File.Exists(theProjectPath))
            {
                Console.WriteLine("The project file already exists.");
                return null;
            }

            HighSpeedFileStore hfs = null;
            IProject aProject = null;

            // Create the HighSpeedFileStore and set the store path
            hfs = new HighSpeedFileStore(rootPath);
            hfs.StorePath = storePath;

            if (null == hfs)
            {
                Console.WriteLine("The datastore could not be created.");
                return null;
            }

            // Create the project
            aProject = Inspector.ProjectFactory.Create(hfs, projectName);
            if (null == aProject)
            {
                Console.WriteLine("Failed to create a new project.");
                return null;
            }

            return aProject;
        }

        // this function opens an existing project file and associates it with the returned IProject
        static IProject OpenProject(string theProjectPath)
        {
            string storePath = theProjectPath.Substring(0, theProjectPath.LastIndexOf("\\"));
            string rootPath = storePath.Substring(0, storePath.LastIndexOf("\\"));
            rootPath = rootPath.Substring(0, rootPath.LastIndexOf("\\"));
            string projectName = theProjectPath.Substring(theProjectPath.LastIndexOf("\\") + 1);
            projectName = projectName.Substring(0, projectName.LastIndexOf("."));

            // make sure we create the directory
            if (!Directory.Exists(storePath))
            {
                Directory.CreateDirectory(storePath);
            }

            if (false == System.IO.File.Exists(theProjectPath))
            {
                Console.WriteLine("[E] Could not find the project specified");
                return null;
            }

            HighSpeedFileStore hfs = null;
            IProject aProject = null;

            // Try to create the HighSpeedFileStore for the project
            try
            {
                Inspector.EventManager.BeginBulkUpdate();

                Stream stream = new FileStream(theProjectPath, FileMode.Open, FileAccess.Read, FileShare.Read);

                hfs = new HighSpeedFileStore(stream);

                hfs.RootPath = rootPath;
                hfs.StorePath = storePath;
                stream.Close();

                System.GC.Collect(0);
                System.GC.WaitForPendingFinalizers();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Inspector.EventManager.EndBulkUpdate();
                return null;
            }

            if (null == hfs)
            {
                Console.WriteLine("[E] Could not create HighSpeedFileStore for the project");
                return null;
            }

            // Try to create the project from the HFS
            try
            {
                aProject = Inspector.ProjectFactory.Create(hfs, projectName);
            }
            catch (Exception Ex)
            {
                Inspector.EventManager.EndBulkUpdate();
                Console.WriteLine(Ex.Message);
                return null;
            }

            Inspector.EventManager.EndBulkUpdate();
            return aProject;
        }

        // this function saves the given project back out to disk
        static bool SaveProject(IProject theProject)
        {
            try
            {
                // make sure we create the directory
                if (!Directory.Exists(theProject.DataStore.RootPath))
                {
                    Directory.CreateDirectory(theProject.DataStore.RootPath);
                }

                if (!Directory.Exists(theProject.DataStore.StorePath))
                {
                    Directory.CreateDirectory(theProject.DataStore.StorePath);
                }

                Stream stream = new FileStream(
                    theProject.DataStore.StorePath + "\\" + theProject.DataStore.StoreName + ".proj",
                    FileMode.Create, FileAccess.Write, FileShare.Write);

                HighSpeedFileStore hfs = (HighSpeedFileStore)theProject.DataStore;

                hfs.ToStream(stream);

                stream.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error while trying to save project: " + ex.Message);
                return false;
            }
            return true;
        }

        // this function will construct an analyzer plugin, it requires an open project first
        static IBinaryAnalyzer BuildAnalyzer(string theAnalyzerName, IProject theProject)
        {
            ILoader iloader = new InspectorLoader(_toolDirectory);
            if (iloader == null)
            {
                Console.WriteLine("Failed to build ILoader");
                return null;
            }

            IBinaryAnalyzer ianalyzer = iloader.BuildAnalyzer(theAnalyzerName, theProject);
            if (ianalyzer == null)
            {
                Console.WriteLine("Failed to build IBinaryAnalyzer");
                return null;
            }
            return ianalyzer;
        }
    }
}
