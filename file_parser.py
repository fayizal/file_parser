import Image, stepic
import binascii
import sys
import re
import csv
from PIL import Image
from PIL.ExifTags import TAGS
import simplekml
import os, time
import hashlib
from stat import * 
from pyads import ADS
import layout_scanner
import rarfile



def process(stream,pattern):
    data = stream.read()
    return pattern.findall(data)

###Reference https://github.com/dpapathanasiou/pdfminer-layout-scanner/blob/master/layout_scanner.py
def pdf_extract(filename):
    
    fp = open('output\pdf.txt', 'wb')
    pages=layout_scanner.get_pages(filename)
    # Calculating number of pages for the PDF document
    length=len(pages)
    i=0
    # Running the loop and saving text contents for each page
    while i<length:
        fp.write(pages[i]+"\n")
        i=i+1
    fp.close()

### Reference : http://effbot.org/zone/python-fileinfo.htm
### Reference : http://stackoverflow.com/questions/16874598/how-do-i-calculate-the-md5-checksum-of-a-file-in-python
def filetype(filename):
    # Calculating hash function for the file
    hsh =  hashlib.md5(filename).hexdigest()
    file=open("output\summary.txt","a")
    file.write("******************************************************\n")
    file.write("Filename: " + filename + "\n")
    file.write("Hash: " + hsh + "\n")
    file.write("------------------------------------------------------\n")
    
    print "******************************************"
    print "All Results Stored inside output directory"
    print "******************************************"
    file.write("File Name : " + filename + "\n")
    print "File Name : " + filename
    hsh =  hashlib.md5(filename).hexdigest()
    file.write("File Hash : " + hsh+ "\n")
    print "File Hash : " + hsh

    # Storing File metadata info for processing
    try:
        st = os.stat(filename)
    except IOError:
        print "Failed to get information about : ", filename
    else:
        # Saving file timestamp info
        file.write("File size: " + str(st[ST_SIZE])+ "\n")
        print "File size: ", st[ST_SIZE]
        file.write("File modified: " + str(time.asctime(time.localtime(st[ST_MTIME])))+ "\n")
        print "File modified: ", time.asctime(time.localtime(st[ST_MTIME]))
        file.write("File modified: " +  str(time.asctime(time.localtime(st[ST_MTIME])))+ "\n")
        print "File Last Accessed : ", time.asctime(time.localtime(st[ST_ATIME]))
        file.write("File Last Accessed : "+ str(time.asctime(time.localtime(st[ST_ATIME])))+ "\n")
        print "File Created : ", time.asctime(time.localtime(st[ST_CTIME]))
        file.write("File Created : "+ str(time.asctime(time.localtime(st[ST_CTIME])))+ "\n")


        
    f=open(filename, 'rb')
    i=0
    header=""

    # Opening filetype.dat which contains file signature information
    ifile  = open('filetype.dat', "rb")
    reader = csv.reader(ifile)
    rownum=0
    filesig="None"
    ftype="NA"
    while i<30:
        content = f.read(1)
        if not content:
            break
        else:
            temp=binascii.hexlify(content)
            if header != "":
                header=header + " " + temp 
            else:
               header=header + temp 
            ifile  = open('filetype.dat', "rb")
            reader = csv.reader(ifile)
            for row in reader:
               if header.lower() == row[0].lower():
                   filesig=row[1]
                   ftype=row[2]
        i=i+1
    print "Similar to filetype : " + filesig
    file.write("\nSimilar to filetype : " + filesig + "\n")
    file.write("------------------------------------------------------\n")
    file.close()
    return ftype

### Reference : http://stackoverflow.com/questions/6804582/extract-strings-from-a-binary-file-in-python
def display_strings(filename):
    hsh =  hashlib.md5(filename).hexdigest()
    file=open("output\strings.txt","a")
    file.write("******************************************************\n")
    file.write("Filename: " + filename + "\n")
    file.write("Hash: " + hsh + "\n")
    file.write("------------------------------------------------------\n")
    # Defining the character set which is to be extracted as string
    chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
    shortest_run = 4
    regexp = '[%s]{%d,}' % (chars, shortest_run)
    pattern = re.compile(regexp)
    f=open(filename,'rb')
    # looping the entire file to search for strings 
    for found_str in process(f,pattern):
        file.write(str(found_str)+"\n")
    # Detecting if there is an NTFS ADS within the file  	
    try:
        handler=ADS(filename)
        if handler.containStreams():
            for stream in handler.getStreams():
                file.write("NTFS Stream Found  : " + str(stream) +"\n")
                print "NTFS Stream Found  : " + stream
                file.write("Contents of NTFS Stream is : ")
                print "Contents of NTFS Stream is : ",
                file.write(handler.getStreamContent(stream) + "\n")
                print handler.getStreamContent(stream)
    except:
        file.write("No NTFS Stream found for the file")
        print "No NTFS Stream found for the file"

    file.write("------------------------------------------------------\n")
    file.close()
    
### Reference : http://www.linuxforu.com/2010/05/cryptography-and-steganography-with-python/
### Reference : http://stackoverflow.com/questions/765396/exif-manipulation-library-for-python
### Reference : https://code.google.com/p/simplekml/
def get_exif(fn):

    hsh =  hashlib.md5(fn).hexdigest()
    ret = {}
    file=open("output\exif.txt","a")
    file.write("******************************************************\n")
    file.write("Filename: " + fn + "\n")
    file.write("Hash: " + hsh + "\n")
    file.write("------------------------------------------------------\n")
    i = Image.open(fn)
    # Detecting if there is steganography
    try:
        data=stepic.decode(i)
        print "Secret Text Message: " + data
        file.write("Secret Text Message: " + data +"\n")
    except:
        print "No Steganography Found"
        file.write("\nNo Steganography Found\n")
    try:
        info = i._getexif()
        
    # Parsing the image and extracting EXIF info

        for tag, value in info.items():
        
            decoded = TAGS.get(tag, tag)
            ret[decoded] = value
            file.write(str(decoded)+": " + str(ret[decoded]) + "\n")
            
            temp=str(decoded).lower()
            
     # Extracting GPS Related Info

            if temp == 'gpsinfo':
                
                lat = [float(x)/float(y) for x, y in ret['GPSInfo'][2]]
                latref = ret['GPSInfo'][1]
                lon = [float(x)/float(y) for x, y in ret['GPSInfo'][4]]
                lonref = ret['GPSInfo'][3]
                lat = lat[0] + lat[1]/60 + lat[2]/3600
                lon = lon[0] + lon[1]/60 + lon[2]/3600
                if latref == 'S':
                    lat = -lat
                if lonref == 'W':
                    lon = -lon
     # Saving GPS Cordinates as KML file
                kml = simplekml.Kml()
                kml.newpoint(name=fn, coords=[(lon,lat)])
                kml.save("output\info.kml")
    except:
        file.write("NO EXIF Tags Found\n")
        print "NO EXIF Tags Found"

    file.write("------------------------------------------------------\n")
    file.close()

### Reference : http://stackoverflow.com/questions/273192/create-directory-if-it-doesnt-exist-for-file-write
def create_directory(directory):
    #Create the directory to store results
    if not os.path.exists(directory):
        os.makedirs(directory)

### Reference : http://rarfile.berlios.de/doc/
def rar_info(fn):
    hsh =  hashlib.md5(fn).hexdigest()
    file=open("output\\rar.txt","a")
    file.write("******************************************************\n")
    file.write("Filename: " + fn + "\n")
    file.write("Hash: " + hsh + "\n")
    file.write("------------------------------------------------------\n")
    # Extract files inside the RAR archive
    rf = rarfile.RarFile(fn)
    i=1
    for f in rf.infolist():
       file.write("Archive File" + str(i) + ": \"" + f.filename + "\" File Size : " + str(f.file_size) +"\n")
       i=i+1
       try:
           # Extract the file contents inside RAR  
           file.write("\n" + "-----------File Contents------------------" + "\n")
           file.write(str(rf.read(f))+"\n")
       except:
           print("Unable to read" + f.filename +"\n")
       file.write("----------------------------------------\n")
    file.write("------------------------------------------------------\n")
    file.close()



##############################  Main Starts Here  ########################################3

if  __name__ =='__main__':

# Initialize file type to NULL 

    type="NULL"


# Create the directory for storing results

    create_directory("output")


# Get the filename from command line parameter

    filename=sys.argv[1]

# Display Strings inside the file
	
    display_strings(filename)

# Display the type of file

    type=filetype(filename)


# If Image then try to retrieve EXIF Info

    if type == "image":
        get_exif(filename)

# If PDF then extract pdf info

    if type == "pdf":
        pdf_extract(filename)

# If RAR then extract file info

    if type == "rar":
        rar_info(filename)

   

