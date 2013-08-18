import Image
import stepic
import ezPyCrypto
import sys
im=Image.open(sys.argv[1])
im1=stepic.encode(im,sys.argv[2])
im1.save('encoded.png','PNG')
