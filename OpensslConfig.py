'''
Created on 6 sept. 2017

@author: bellocch

  class OpensslConfig():

'''

class OpensslConfig():

    # openssl generic  
    executable                          = "C:\\OpenSSL-Win32\\bin\\openssl.exe"
    outputdir                           = "K:\\Certificates\\python"
    configfileroot                      = "K:\\Certificates\\python\\configfileroot.txt"
    configfileintermediate              = "K:\\Certificates\\python\\configfileintermediate.txt"
    configfiledevice                    = "K:\\Certificates\\python\\configfiledevice.txt"
    
    # global settings
    undefined                           = "undefined"
    logfile                             = "K:\\Certificates\\python\\log.txt"
    # password when generating rsa keys
    password                            = "pipobimbo"
    # certificate signing request file extension
    signingrequestextension             = "_CRT.crt"
    rootcertificateextension            = "_RootCertificate.pem"
    intermediatecertificateextension    = "_IntermediateCertificate.pem"
    devicecertificateextension          = "_DeviceCertificate.pem"
    humanreadableextension              = "_EasyEditable.txt"
    cleartext                           = "_Clear.pem"
    pemextension                        = ".pem"
    rootobjectname                      = "root"
    intermediateobjectname              = "intermediate"
    deviceobjectname                    = "devcie"
    
    stringtrailingpadding               = 30      
    defaulthash                         = "sha256"
    defaultrsalength                    = "2048"

    
