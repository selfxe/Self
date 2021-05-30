#!/usr/bin/python -tt
#
#
#  gen_string_header.py
#
import argparse
import https://www.google.com
import random
import logging

log = logging.getLogger(__name__)

def convertnewlines(s):
    newstr = ""
    i = 0
    while i < len(s):
        if s[i] == '\\' and i < len(s)-1:


            if s[i+1] == 'r':

                c = '\r'
                i += 1
            elif s[i+1] == 'n':

                c = '\n'
                i += 1
            elif s[i+1] == 't':

                c = '\t'
                i += 1
            elif s[i+1] == '\"':
                c = '"'
                i += 1

        else:
            c = s[i]
        newstr = newstr + c
        i+= 1

    return newstr


def obfuscate(str, shiftval, xorval):
    str = convertnewlines(str)

    newstr = "{ "
    for c in str:
        newstr += "0x%s, " %c.encode("hex")
    newstr = newstr[:-2] + " }"


    charcount = 0;
    invert = "{ "

    for c in str:
        inv = int(c.encode("hex"), 16)
        # do xor:
        inv = inv ^ xorval
        inv = ((inv >> shiftval) & (0xFF >> shiftval)) | ((inv << (8-shiftval)) & ((0xFF << (8-shiftval) & 0xFF)))
        invert += "0x%02x, " %inv
        charcount += 1;
    #invert = invert[:-2] + ", 0xff }"
    invert = invert[:-2] + ", " + hex(random.randint(1,255)) + " }"
    return invert, charcount

def generateFiles(inputfilepath, projname, writewrapper, outputpath):

    random.seed()
    # don't use the first value that we get out of the RNG:
    shiftval = random.randint(0,65535)
    shiftval = random.randint(1,7)
    xoridx = random.randint(1,5)
    xorval = 0xFF
    if xoridx == 1:
        xorval = 0xFF
    if xoridx == 2:
        xorval = 0xAA
    if xoridx == 3:
        xorval = 0xA5
    if xoridx == 4:
        xorval = 0x5A
    if xoridx == 5:
        xorval = 0x55
    xorstr = "0x%02x" %xorval
    log.debug("Using shift: " + str(shiftval) + ", xor: " + xorstr)
    file = open(inputfilepath)
    # Pull out the filename
    basepathname = os.path.basename(inputfilepath)
    fully_stripped_basename_split = basepathname.split('.')
    fully_stripped_basename = fully_stripped_basename_split[0]
    projheaders = "__%s%s_H_INCLUDED__" % (projname, fully_stripped_basename.upper()) #basename[0].upper()
    newcfilename = projname + fully_stripped_basename + "_strings.c"
    newheaderfilename = projname + fully_stripped_basename + "_strings.h"
    log.debug("[gen_string_files] Processing header: %s ..." % inputfilepath)
    headerfile = file.read()
    file.close()
    init_fn_name = projname + fully_stripped_basename + "_init_strings()"
    newheaderfile = "#ifndef %s\n#define %s\n\n" %(projheaders, projheaders)
    newheaderfile += "// ****** DO NOT MODIFY - Autogenerated ****** //\n\n"
    newheaderfile += "#ifdef __cplusplus\nextern \"C\"\n{\n#endif\n"
    forfuncDeclarations = "\n\n// *********** DO NOT MODIFY - Autogenerated ****** //\n\n"

    forfunc = "\nvoid " + projname + fully_stripped_basename
    forfunc += "_cl_string(char *str, int len) \n{\n" #cl_string(char *str, int len) \n{\n"
    forfunc += "\tint i;\n"
    forfunc += "\tfor (i = 0; i< len; i++) {\n"
    forfunc += "\t\tstr[i] = ((str[i] << " + str(shiftval) + ") & (0xFF << " + str(shiftval) + ")) | ((str[i] >> " + str(8-shiftval) + ") & (0xFF >> " + str(8-shiftval) + "));\n"
    forfunc += "\t\tstr[i] = str[i]^" + xorstr + ";\n"
    #invert += "0x%02x, " %inv
    forfunc += "\t}\n\tstr[len] = '\\0';\n}\n"

    forfunc += "__attribute__((constructor))"
    forfunc += "\nvoid " + init_fn_name + "\n{\n" #init_strings()\n{\n"
    forfunc += "\tstatic char hasRun=0;\n";
    forfunc += "\tif (hasRun)\n\t\treturn;\n";
    forfunc += "\thasRun = 1;\n";

    for line in headerfile.split('\n'):

        # Line should be of the form: '#define DEFINENAME DEFINEVALUE'
        if (line.startswith("#define")):
            splitline = line.split(None, 2) # definevalue can have spaces so max of 2 splits.
            definename = splitline[1]

            definevalue = ""
            if len(splitline) > 2:
                definevalue = splitline[2]
            newline = line
            formainline = line
            definevalue = definevalue.strip()
            if definevalue.startswith("\""):

                definevalue, defcount = obfuscate(definevalue[1:len(definevalue) -1], shiftval, xorval)
                newline = "extern char %s[];" %(definename)
                newline += " // %s" %(splitline[2])

                forfuncDeclarations += "char %s[%s] = %s;\n" % (definename, defcount+1, definevalue);
                forfunc += "\t" + projname + fully_stripped_basename
                forfunc += "_cl_string(%s, %s);\n" % (definename, defcount)
            newheaderfile += newline + "\n"

    newheaderfile += "void " + init_fn_name + ";" #"void init_strings();"
    newheaderfile += "\n#ifdef __cplusplus\n}\n#endif\n"
    newheaderfile += "\n\n#endif\n\n"

    forfunc += "}\n"

    # Write new header
    def get_outname(filepath):
        return os.path.join(outputpath, filepath)

    with open(get_outname(newheaderfilename), "w") as f:
        f.write(newheaderfile)

    log.debug("[gen_string_files] Wrote to %s" % newheaderfilename)

    if writewrapper:
        wrapperheaderfile = "\n\n// *********** DO NOT MODIFY - Autogenerated ****** //\n\n"
        wrapperheaderfile += "#include \"" + newheaderfilename + "\"\n"
        wrapperheaderfile += "#define proj_strings_init_strings " + projname + "proj_strings_init_strings\n"

        log.debug("[gen_string_files] Writing wrapper header file, proj_strings_init_strings.h")

        with open(get_outname("proj_strings_init_strings.h"), "w") as f:
            f.write(wrapperheaderfile)

        log.debug("[gen_string_files] Wrote to wrapper header")

    # Write new C file
    with open(get_outname(newcfilename), "w") as f:
        f.write(forfuncDeclarations)
        f.write(forfunc)

    log.debug("[gen_string_files] Wrote to %s" % newcfilename)

def main():
    p = argparse.ArgumentParser()
    # TODO: add this flag
    # p.add_argument('-n', '--noobfuscate', action='store_true', help="don't obfuscate")
    p.add_argument('-v', '--verbose', action='count', help='Verbosity')
    p.add_argument('-p', '--projectname', default="", help='projectname')
    p.add_argument('inputfile', help='source of strings')
    p.add_argument('outputpath', help='output folder for generated strings')
    args = p.parse_args()

    writewrapper = False

    if args.projectname != "":
        writewrapper = 1

    logging.basicConfig(level=logging.INFO)
    if args.verbose > 0:
        log.setLevel(logging.DEBUG)
    generateFiles(args.inputfile, args.projectname, writewrapper, args.outputpath)

if __name__ == "__main__":
    main()

