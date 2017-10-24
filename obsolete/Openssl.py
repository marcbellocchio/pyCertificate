'''
Created on 5 sept. 2017

@author: bellocch
'''
import cmd
import sys
# from GenRoot import GenRoot
from GenRoot import  GenRoot
from GenIntermediate import  GenIntermediate
from OpensslTracking import OpensslTracking


class OpenSSLCommandparser(cmd.Cmd):
    """OpenSSL from Python Please start from here"""
    
    prompt = 'Main>>: '

    def __init__(self, pstdin=None):   
        super(OpenSSLCommandparser, self).__init__(stdin=pstdin)        
        # or cmd.Cmd.__init__(self)    
        if pstdin is not None:
            # Disable rawinput module use when stdin is a script
            self.use_rawinput = False
        # tracking object used by all classes, the cache is global for all     
        self.tracking           = OpensslTracking()

    def do_SetSessionName (self, line):
        """ give a name to the session and append it to all the output rsa and certificate file name"""
        OpensslTracking.session = line
        
    def do_Root (self, line):
        """ access to ROOT certificates"""
        GenRoot(self.stdin, self.tracking).do_cmdloop()
        
    def do_Intermediate (self, line):
        """ access to INTERMEDIATE certificates"""
        GenIntermediate(self.stdin, self.tracking).do_cmdloop()
    
    def do_Device (self, line):
        """ access to DEVICE certificates"""
    
    def do_exit(self,*args):
        """ to exit from main program"""
        return True

if __name__ == '__main__':
    #OpenSSLCommandparser().cmdloop()
    # activate logging
    
    #try:
        #logging.basicConfig(level=logging.INFO,
        #               filename=OpensslConfig.logfile, filemode='a',
        #              format='%(name)s %(levelname)s %(message)s')
        
    #except IOError:
    #    print("error while setting logging class")
    
    if len(sys.argv) > 1:
        try:
            ifile = open(sys.argv[1], 'rt')
        except IOError:
            print ("error trying to open script file : ", sys.argv[1] ,"\nstarting command line" )
        else: # ok for file, lets try it
            print("starting script:", sys.argv[1] )
            OpenSSLCommandparser(pstdin=ifile).cmdloop()              
        finally:
            print ("finally file is : ", sys.argv[1])
            ifile.close()
  
    else: # manual mode
        OpenSSLCommandparser().cmdloop()        