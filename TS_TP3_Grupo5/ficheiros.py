from __future__ import with_statement
import os
import stat
import sys
import errno
from pwd import getpwuid
import hashlib
import logging
import logging.handlers
import pyotp
import socket
import subprocess
from fuse import FUSE, FuseOSError, Operations, fuse_get_context

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65430  # Port to listen on (non-privileged ports are > 1023)

class Passthrough(Operations):
    def __init__(self, root):
        self.root = root
        self.log= setup_custom_logger(root)
        self.socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((HOST,PORT))
        self.list_perm={}
        self.ptotp=pyotp.TOTP("JBSWY3DPEHPK3PXP")
        os.chmod("log.txt", stat.S_IRWXU|0|0)

    def full_path(self,partial):
        if partial.startswith("/"):
            partial=partial[1:]
        path =os.path.join(self.root,partial)

        return path
    
    
    def access(self,path,mode):
        full_path=self.full_path(path)
        print("access")
       
        if not os.access(full_path,mode):
            raise FuseOSError(errno.EACCES)
        
    def chmod(self, path, mode):
        full_path = self.full_path(path)
        st = os.lstat(full_path)
        uid, gid, pid = fuse_get_context()
        if(st.st_uid==uid):
            self.log.info("Permissão alterada " +"para o ficheiro " + full_path.split("/")[-1])
            return os.chmod(full_path, mode)
        else:
            raise FuseOSError(errno.EACCES)
 
    def chown(self, path, uid, gid):
        full_path = self.full_path(path)
        return os.chown(full_path, uid, gid)

    def readdir(self, path, fh):
        full_path = self.full_path(path)
        dirents = ['.', '..']
        if os.path.isdir(full_path):
             dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r
    
    
    def getattr(self, path, fh=None):
        full_path = self.full_path(path)
        st = os.lstat(full_path)
        uid, gid, pid = fuse_get_context()
    
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
    
    def readlink(self, path):  
        pathname = os.readlink(self.full_path(path))
        if pathname.startswith("/"):
           # Path name is absolute, sanitize it.
             return os.path.relpath(pathname, self.root)
        else:
           return pathname

    def mknod(self, path, mode, dev):
       return os.mknod(self.full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self.full_path(path)
        uid, _, _ = fuse_get_context()
        self.log.warning('O utilizador '+ getpwuid(uid).pw_name + " eleminou a diretoria " + full_path.split("/")[-1])
        return os.rmdir(full_path)
    
    def mkdir(self,path,mode):
        full_path = self.full_path(path)
        uid, gid, pid = fuse_get_context()
        self.log.info('O utilizador '+ getpwuid(uid).pw_name + " criou a diretoria " + full_path.split("/")[-1])
        return os.mkdir(full_path,mode)

    def statfs(self, path):
        full_path = self.full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        print("unlink")
        return os.unlink(self.full_path(path))

    def symlink(self, name, target):
        return os.symlink(name, self.full_path(target))

    def rename(self, old, new):
        return os.rename(self.full_path(old), self.full_path(new))
 
    def link(self, target, name):
        return os.link(self.full_path(target), self.full_path(name))
 
    def utimens(self, path, times=None):
        return os.utime(self.full_path(path), times)
    
    
    def open(self, path, flags):
        print("open")
        full_path = self.full_path(path)
        st = os.lstat(full_path)
        perm=permissions_to_unix_name(st)
        uid, gid, _ = fuse_get_context()
        if full_path not in self.list_perm:
            self.list_perm[full_path]=[]
        if getpwuid(uid).pw_name in self.list_perm[full_path]:
            self.log.info('O utilizador '+ getpwuid(uid).pw_name + " abriu o ficheiro " + full_path.split("/")[-1])
            return os.open(full_path, flags)
        if((uid==st.st_uid)):
            aux=perm[1:4]
            if aux=='---':
                self.socket.listen()
                openBrowser()
                conn, addr = self.socket.accept()
                data = conn.recv(1024)
                code=self.ptotp.now()
                if(data.decode()==code):
                    self.log.info('Foi concedida permissão ao utilizador '+ getpwuid(uid).pw_name + " para abrir o ficheiro " + full_path.split("/")[-1])
                    self.list_perm[full_path].append(getpwuid(uid).pw_name)
                    return os.open(full_path, flags)
                else:
                    self.log.warning('O utilizador '+ getpwuid(uid).pw_name + " tentou abrir o ficheiro " + full_path.split("/")[-1])
                    raise FuseOSError(errno.EACCES)
        elif(gid==st.st_gid):
                aux=perm[4:7]
                if(aux=='---'):
                    self.socket.listen()
                    openBrowser()
                    conn, addr = self.socket.accept()
                    data = conn.recv(1024)
                    code=self.ptotp.now()
                    if(data.decode()==code):
                        self.log.info('Foi concedida permissão ao utilizador '+ getpwuid(uid).pw_name + " para abrir o ficheiro " + full_path.split("/")[-1])
                        self.list_perm[full_path].append(getpwuid(uid).pw_name)
                        return os.open(full_path, flags)
                    else:
                        self.log.warning('O utilizador '+ getpwuid(uid).pw_name + " tentou abrir o ficheiro " + full_path.split("/")[-1])
                        raise FuseOSError(errno.EACCES)
        else:
            aux=perm[7:10]
            if(aux=='---'):
                self.socket.listen()
                openBrowser()
                conn, addr = self.socket.accept()
                data = conn.recv(1024)
                code=self.ptotp.now()
                if(data.decode()==code):
                    self.log.info('Foi concedida permissão ao utilizador '+ getpwuid(uid).pw_name + " para abrir o ficheiro " + full_path.split("/")[-1])
                    self.list_perm[full_path].append(getpwuid(uid).pw_name)
                    return os.open(full_path, flags)
                else:
                    self.log.warning('O utilizador '+ getpwuid(uid).pw_name + " tentou abrir o ficheiro " + full_path.split("/")[-1])
                    raise FuseOSError(errno.EACCES)

        self.log.info('O utilizador '+ getpwuid(uid).pw_name + " abriu o ficheiro " + full_path.split("/")[-1])
        return os.open(full_path, flags)
        
   
    def create(self, path, mode, fi=None):
        print("create")
        full_path = self.full_path(path)
        uid, _, _ = fuse_get_context()
        self.log.info('O utilizador '+ getpwuid(uid).pw_name + " criou o ficheiro " + full_path.split("/")[-1])
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
    
    def read(self, path, length, offset, fh):   
        print("read")
        full_path = self.full_path(path)
        os.lseek(fh, offset, os.SEEK_SET)
        full_path = self.full_path(path)
        uid, gid, _ = fuse_get_context()
        st = os.lstat(full_path)
        perm=permissions_to_unix_name(st)
        if((uid==st.st_uid)):
            aux=perm[1:4]
            if aux[0]=='r':
                self.log.info('O utilizador '+ getpwuid(uid).pw_name + " leu o ficheiro " + full_path.split("/")[-1])
                return os.read(fh, length)
        elif(gid==st.st_gid):
            aux=perm[4:7]
            if(aux[0]=='r'):
                self.log.info('O utilizador '+ getpwuid(uid).pw_name + " leu o ficheiro " + full_path.split("/")[-1])
                return os.read(fh, length)
        else:
            aux=perm[7:10]
            if(aux[0]=='r'):
                self.log.info('O utilizador '+ getpwuid(uid).pw_name + " leu o ficheiro " + full_path.split("/")[-1])
                return os.read(fh, length)
      
        if getpwuid(uid).pw_name in self.list_perm[full_path]:
            self.log.info('O utilizador '+ getpwuid(uid).pw_name + " leu o ficheiro " + full_path.split("/")[-1])
            return os.read(fh, length)
        self.socket.listen()
        openBrowser()
        conn, _ = self.socket.accept()
        data = conn.recv(1024)
        code=self.ptotp.now()
        if(data.decode()==code):
            self.log.info('Foi concedida permissão ao utilizador '+ getpwuid(uid).pw_name + " para ler o ficheiro " + full_path.split("/")[-1])
            self.list_perm[full_path].append(getpwuid(uid).pw_name)
            return os.read(fh, length)
        
        else:
            self.log.warning('O utilizador '+ getpwuid(uid).pw_name + " tentou ler o ficheiro " + full_path.split("/")[-1])
            raise FuseOSError(errno.EACCES)
        
        
    def write(self, path, buf, offset, fh):
        print("write")
        full_path = self.full_path(path)
        os.lseek(fh, offset, os.SEEK_SET)
        full_path = self.full_path(path)
        uid, gid, _ = fuse_get_context()
        st = os.lstat(full_path)
        perm=permissions_to_unix_name(st)
        if((uid==st.st_uid)):
            aux=perm[1:4]
            if aux[1]=='w':
                self.log.info('O utilizador '+ getpwuid(uid).pw_name + " escreveu o ficheiro " + full_path.split("/")[-1])
                return os.write(fh, buf)
        elif(gid==st.st_gid):
            aux=perm[4:7]
            if(aux[1]=='w'):
                self.log.info('O utilizador '+ getpwuid(uid).pw_name + " escreveu o ficheiro " + full_path.split("/")[-1])
                return os.write(fh, buf)
        else:
            aux=perm[7:10]
            if(aux[1]=='w'):
                self.log.info('O utilizador '+ getpwuid(uid).pw_name + " escreveu o ficheiro " + full_path.split("/")[-1])
                return os.write(fh, buf)
        if getpwuid(uid).pw_name in self.list_perm[full_path]:
            self.log.info('O utilizador '+ getpwuid(uid).pw_name + " escreveu o ficheiro " + full_path.split("/")[-1])
            return os.write(fh, buf)
        self.socket.listen()
        openBrowser()
        conn, _ = self.socket.accept()
        data = conn.recv(1024)
        code=self.ptotp.now()
        if(data.decode()==code):
            self.log.info('Foi concedida permissão ao utilizador '+ getpwuid(uid).pw_name + " para escrever o ficheiro " + full_path.split("/")[-1])
            self.list_perm[full_path].append(getpwuid(uid).pw_name)
            return os.write(fh, buf)
        
        else:
            self.log.warning('O utilizador '+ getpwuid(uid).pw_name + " tentou escrever o ficheiro " + full_path.split("/")[-1])
            raise FuseOSError(errno.EACCES)
       
        
        
    def truncate(self, path, length, fh=None):
        full_path = self.full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def openBrowser():
        myEnv = dict(os.environ)

        toDelete = [] 
        for (k, v) in myEnv.items():
            if k != 'PATH' and 'tmp' in v:
                toDelete.append(k)

        for k in toDelete:
            myEnv.pop(k, None)

        shell = False
        if sys.platform == "win32":
            opener = "start"
            shell = True
        elif sys.platform == "darwin":
            opener = "open"
        else: # Assume Linux
            opener = "xdg-open"

        subprocess.call([opener, 'index.html'], env=myEnv, shell=shell)    
        


def hash_G1(data):
        h = hashlib.sha3_512()
        h.update(data)
        return h.digest()

def permissions_to_unix_name(st):
        is_dir = 'd' if stat.S_ISDIR(st.st_mode) else '-'
        dic = {'7':'rwx', '6' :'rw-', '5' : 'r-x', '4':'r--','3':'-wx','2':'-w-','1':'--x' ,'0': '---'}
        perm = str(oct(st.st_mode)[-3:])
        return is_dir + ''.join(dic.get(x,x) for x in perm)


def full_path(partial,root):
    if partial.startswith("/"):
            partial=partial[1:]
    path =os.path.join(root,partial)
    return path


    

def metaDados(root):

    f_write=open("metadados.txt","w")
    f_write.write("Para obtenção do código otp contacte : facahd@gmail.com\n\n")
    for (root, dirs, file) in os.walk(root):
        for d in dirs:
            path1=str(root)+"/"+str(d)
            st2=os.lstat(path1)
            perm=permissions_to_unix_name(st2)
            f_write.write(str(d)+" "+getpwuid(st2.st_uid).pw_name + " "+ getpwuid(st2.st_gid).pw_name+ " "+str(perm)+"\n")
        for f in file:
            path1=str(root)+"/"+str(f)
            st=os.lstat(path1)
            perm=permissions_to_unix_name(st)
            hash=b""
            f1=open(path1,mode='rb')
            (f1.read())
            conteudo=f1.read()
            f1.close()
            hash=hash_G1(conteudo)
            f_write.write(str(f)+" "+getpwuid(st.st_uid).pw_name+ " "+getpwuid(st.st_gid).pw_name+ " "+str(perm)+" "+str(hash)+"\n")
    os.chmod("metadados.txt", stat.S_IRWXU| stat.S_IRGRP|stat.S_IROTH )



def setup_custom_logger(name):
    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.FileHandler('log.txt', mode='w')
    handler.setFormatter(formatter)
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.addHandler(screen_handler)
    return logger
    
    

def main(mountpoint,root):
    metaDados(root)
    FUSE(Passthrough(root),mountpoint,nothreads=True,foreground=True,allow_other=True)

if __name__ == '__main__':
    main(sys.argv[2],sys.argv[1])