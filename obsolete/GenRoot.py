'''
Created on 6 sept. 2017

@author: bellocch
'''

import cmd
import sys
from subprocess import call #, STDOUT
from time import   strftime, localtime
from OpensslConfig import OpensslConfig
from OpensslTracking import OpensslTracking

class GenRoot(cmd.Cmd):
    """
    input: pstdin is the input to use from main process
           trackingobject is the tracking class from main used to cache object
    """
    prompt = 'Root>>: '

    def __init__(self, pstdin, trackingobject ):
        #get  
        super(GenRoot, self).__init__(stdin=pstdin)      
        self.hash               = "sha256"
        self.rsalength          = "2048"
        self.hashlist           = [ 'sha1', 'sha256']
        self.name               = OpensslConfig.rootobjectname
        self.rsakeyname         = OpensslConfig.undefined
        self.csrname            = OpensslConfig.undefined
        self.certificatename    = OpensslConfig.undefined
        self.password           = OpensslConfig.password  # default password 
        
        if pstdin is not None:
            # Disable rawinput module use when stdin is a script
            self.use_rawinput   = False
            
        self.tracking           = trackingobject
         
    def GetHash(self):
        return   self.hash     
        
    def do_GenCSR(self, line):   
        """ create signing request from RSA key, any input parameters avoid the use of the config file, parameters of the csr will be done using cli""" 
        if( self.rsakeyname != OpensslConfig.undefined):

            self.csrname = self.rsakeyname + OpensslConfig.signingrequestextension
            if line == "manual":
                cmd = OpensslConfig.executable + " req" + " -new" + " -key " + self.rsakeyname + " -passin pass:" + OpensslConfig.password + " -out "  +  self.csrname 
            else:
                cmd = OpensslConfig.executable + " req" + " -new" + " -key " + self.rsakeyname + " -passin pass:" + OpensslConfig.password + " -out "  +  self.csrname + " -config " + OpensslConfig.configfileroot
            
            #print("cmd:", cmd)
            call(cmd, shell=False)
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.csrname)
            #OpensslTracking().Add("do_GenCSR:: " +  self.csrname + "\n")
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "RSA key shall be generated or select before creating the certificate signing request")
            
    def do_GenCertificate(self, line):   
        """ create certificate """ 
        if( (self.rsakeyname != OpensslConfig.undefined) and (self.csrname !=OpensslConfig.undefined) ):

            self.certificatename = self.rsakeyname + OpensslConfig.rootcertificateextension
            if line == "manual":
                cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.csrname + " -signkey " + self.rsakeyname + " -passin pass:" + OpensslConfig.password + " -" + self.GetHash()  + " -out " +  self.certificatename 
            else:
                cmd = OpensslConfig.executable + " x509 -days 9000" + " -req -in " + self.csrname + " -signkey " + self.rsakeyname + " -passin pass:" + OpensslConfig.password + " -" + self.GetHash() + " -extensions v3_req -extfile "  + OpensslConfig.configfileroot + " -out " +  self.certificatename         
            #print("cmd:", cmd)
            #call(cmd, shell=False, stderr=STDOUT)
            call(cmd, shell=False)
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.certificatename)
            self.CertificateToText()
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "RSA key and certificate signing request  shall be generated or select before creating the certificate")            
        
    def CertificateToText(self):   
        """ txt version of the PEM certificate """ 
                                
        cmd = OpensslConfig.executable + " x509 " + " -in " + self.certificatename + " -text " # +  self.certificatename + OpensslConfig.humanreadableextension
        try:
            file = open(self.certificatename + OpensslConfig.humanreadableextension, 'w')
        except IOError:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, self.certificatename + OpensslConfig.humanreadableextension)
        else:            
            print("cmd:", cmd)
            call(cmd, shell=False, stdout=file)
            file.close()
            self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.certificatename + OpensslConfig.humanreadableextension)
        #OpensslTracking().Add("do_GenCSR:: " +  self.csrname + "\n")

    def do_GenRSAkey (self, line):
        """ only 2048 bit RSA """             
        self.rsakeyname = OpensslConfig.outputdir + "\\RootRSAKey" + "_" + OpensslTracking.session + "_" + strftime("%Y_%m_%d_%H_%M_%S", localtime())  + ".pem"
        cmd = OpensslConfig.executable + " genrsa" + " -aes128" + " -passout pass:" + OpensslConfig.password + " -out "  + self.rsakeyname + " " + self.rsalength 
        #print ("genrsakey cmd is" + cmd)      
        call(cmd, shell=False)
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)
        
        #self.logger().info("GenRSAkey: " + self.rsakeyname )
        #OpensslTracking().Add("GenRSAkey:: " + self.rsakeyname + "\n")
        # generate human readable format
    
    def do_RSAkeyinClear(self, line):
        """  decrypt RSA key
             need password 
        """
        #C:\OpenSSL-Win32\bin\openssl.exe rsa -passin pass:AnoMalocarys#69 -in "%basedir%\RootTestRSAkey2048.pem" -out "%basedir%\RootTestRSAkey2048_NotEncrypted_Clear.pem"
                        
        cmd = OpensslConfig.executable + " rsa" + " -passin pass:" + OpensslConfig.password + " -in " + self.rsakeyname + " -out "  + self.rsakeyname +  OpensslConfig.cleartext
        #print ("genrsakey cmd is" + cmd)      
        call(cmd, shell=False)
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)
    
    def do_SelectRSAkey(self, line):
        """  select a  RSA key from disk, this function accepts a key file as input """
        if ( not(str(line).isspace())  ):    
            self.rsakeyname = line
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.rsakeyname)


    def do_SetPassword(self, line):
        """  set the password for the root rsa key
             optional as te default password is in the configuration file 
        """
        if ( not(str(line).isspace())  ):    
            self.password = line
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, self.password)
        
        
    def do_SelectHash(self, line):
        """default hash is sha256"""
        if ( (not(str(line).isspace())) and (line in self.hashlist) ):  
            if (line == self.hashlist[0] ):
                self.tracking.SetWarning(self, sys._getframe().f_code.co_name, "deprecated hash: "  + self.hashlist[0])
                self.hash = line   
            else:
                self.tracking.SetInfo(self, sys._getframe().f_code.co_name, "hash: "  + line)
                self.hash = line   
        else:
            self.tracking.SetError(self, sys._getframe().f_code.co_name, "Unsupported hash: "+ line + " current hash is : " + self.hash)
        
    def complete_SelectHash(self, text, line, begidx, endidx):
        if not text:
            completions = self.hashlist[:]
        else:
            completions = [ f
                            for f in self.hashlist
                            if f.startswith(text)
                            ]
        return completions        
    
    def do_exit(self,*args):
        """ to exit from Root class"""
        self.tracking.SetInfo(self, sys._getframe().f_code.co_name, "caching object" ) 
        self.tracking.AddToCache(self)   
        """
        fifi = self.tracking.GetFromCache("root")
        if (fifi != None):
            print("fifi name is" + fifi.name)
        """  
        return True
    
    def do_cmdloop(self,*args):
        self.cmdloop()