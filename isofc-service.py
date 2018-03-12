#!/usr/bin/python3
import sys
import os
import subprocess
import pyudev
import time
import simplejson as json
import re
from threading import Thread, Lock, current_thread, Event
from os.path import dirname, abspath
import configparser

## Функция логирования сообщения с указанием даты
# @param message Логируемое сообщение
def Log(message="\n",include_info=True):
    global config
    if include_info:
        log_message = str(str(time.strftime("[%d %b %Y %H:%M:%S] ("))
                        + current_thread().name + ") " + str(message))
    else:
        log_message = str(message)
    print(log_message)
    with open(config["log_filepath"], "a+") as f:
        f.write(log_message + "\n")

## Функция получения ответа от системной команды
# @param cmd - исполняемая команда
# @param shell - нужно ли открытие shell
# @param logging - нужно ли логирование
def getstatusoutput(cmd, shell=True, timeout=0, logging=False):
    pipe = subprocess.Popen(cmd, shell=shell,
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    deadline = time.time() + timeout
    if timeout:
        while pipe.poll() is None and time.time() < deadline:
            time.sleep(.250)
        if pipe.poll() is None:
            pipe.terminate()
            return 256, ""
    sts = pipe.wait()
    output = str.join("", pipe.stdout.readlines())
    if sts is None:
        sts = 0
    if logging and (sts != 0):
        Log(output)
    return sts, output

## Функция получения списка файлов
# Используется для логирования
def FileList(path):
    a = []
    for top, dirs, files in os.walk(path):
        for nm in files:
            a.append(os.path.join(top, nm))
    return a

## Функция проверки на base64
#
def base64p(string):
    if re.match('^(?:[A-Za-z0-9+/]{4})*'
                        + '(?:[A-Za-z0-9+/]{2}=='
                        + '|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$', string):
        return True
    else:
        return False

## Класс обработки USB-устройств
#
class DeviceHandler(Thread):

    ExitFlag = False
    ## Сообщения для вывода на дисплей
    StatusMsg = {
        'Free': 'Free',
        'Connected': 'Connected',
        'Copying': 'Copying',
        'Error': 'Error',
        'MountError': 'Mount error',
        'CopyError': 'Copy error',
        'UmountError': 'Umount error',
        'Connecting': 'Connecting',
        'ConnectingError': 'Connecting error',
        'AuthFileNotFoundError': 'No auth file',
        'AuthSmbError': 'Check log or path',
        'MoreOneLogin': 'Login in use',
        'WrongAuthFileError': 'Wrong aut file',
        'TransferError': 'Transfer error',
        'DisconnectPlease': 'Done',
        'DisconnectAddition': ', extract',
    }

    def __init__(self):
        super().__init__()
        self.RunMonitor()
        self.quit=False

    def run(self):
        self.observer.start()
        Log(self.observer)
        while self.ExitFlag == False:
            pass


    ## Функция, запускающая обработка мониторинга подключения USB устройств к системе
    #
    # @param self - Возвратный указатель
    #
    def RunMonitor(self):
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by('block')

        # Вызов монитора udev - для вновь подключенного или отключенного устройства вызывается новый тред
        self.observer = pyudev.MonitorObserver(
            monitor,
            lambda action,device : self.RunThread(action,device))

    # Создание треда для обработки устройства
    def RunThread(self,action,device):
        if len(str(device.device_node)) == 9:
            curThread = Thread(target=self.Handle(action,device), args=[action, device]).start()


    ## Функция проверки аутефикации на Samba-сервере
    #
    # Идет проверка на существование файла ./isofc_credentials
    #
    # Файл расшифровывается, сверяется serial id устройства в usb порте и serial id из файла аутефикации
    #
    # @param ciphertext - входная строка (зашифрованный текст)
    # @param private_key_path - путь к файлу секретного ключа
    # @param opentext - расшифрованный текст
    def CheckAuth(self, device, usbdirectory):
        try:
            f = open(usbdirectory + "/.isofc_credentials", "r")
            data = f.read().replace('\n', '')
        except IOError as exc:
            if exc.errno == 2:
                return [False, self.StatusMsg['AuthFileNotFoundError']] # Нет файла аутенфикации
            else:
                return None
        Credentials = self.Decrypt(data) # функция расшифровки файла аутенфикации

        if Credentials == 'Error':
            return [False, self.StatusMsg['WrongAuthFileError']]
        try:
            Credentials = json.loads(Credentials)
            serial = device['ID_SERIAL']
        except:
            return [False, self.StatusMsg['WrongAuthFileError']]
        if serial.lower() != Credentials['Serial'].lower():
            Log("Serial ID in credentials (" + Credentials['Serial'].lower()
                + ") is not equal serial ID in usb device ("
                +  serial.lower() + ")")
            return [False, self.StatusMsg['WrongAuthFileError']]

        f.close()

        return [True, Credentials['Login'], Credentials['Password'], serial]

    ## Функция расшифровки файла с данными авторизации
    #
    # Идет проверка на существование файла секретного ключа.
    #
    # Файл расшифровывается последовательно base64 -> rsa с помошью секретного ключа
    # @param ciphertext - входная строка (зашифрованный текст)
    # @param private_key_path - путь к файлу секретного ключа
    # @param opentext - расшифрованный текст
    def Decrypt(self, ciphertext):
        global config
        if not os.path.isfile(config["private_key_path"]):
            Log("Private key not found")
            return 'Error'
        if not base64p(ciphertext):
            Log(".isofc_credentials is not base64, Ciphertext = '"
                + str(ciphertext) + "'")
            return 'Error'
        retcode, opentext = getstatusoutput(
            "echo " + ciphertext + "|base64 -d|openssl rsautl -inkey "
            + config["private_key_path"] + " -decrypt")
        Log("Retcode(decrypt): " + str(retcode))
        if retcode == 0:
            return opentext
        else:
            return 'Error'

    ## Функция монтирования usb
    # @param device - устройство
    def UsbMount(self,device):
        retval, output = getstatusoutput("pmount " + device.device_node)
        return [retval, re.sub(r'dev', 'media', device.device_node)]

    ## Функция размонтирования usb
    # @param device - устройство
    def UsbUmount(self,device):
        retval, output = getstatusoutput("pumount " + re.sub(r'dev', 'media', device.device_node))
        return retval

    ## Функция обработки состояний USB устройства
    # @param action - действие, произведенное с устройством (add или remove)
    def Handle(self,action,device):
        try:
            Log("Action: " + str(action) + ", "
                + "DEVNAME: " + str(device['DEVNAME']) + ", "
                + "ID_SERIAL: " + str(device['ID_SERIAL']) + " ")
        except:
            Log("Fail on Port: " + str(Port(device)) + ", "
                + "Action: " + str(action))
            return None

        if str(action) == "add":
            retval, usbdirectory = self.UsbMount(device)

            if retval != 0:
                Log("Cannot mount " + str(device.device_node))
                return None

            Log(str(device.device_node) + " mounted")

            Credentials = self.CheckAuth(device, usbdirectory)

            if not Credentials[0]:
                Log(Credentials[1])
            else:
                Log(str(device.device_node) + ", "
                    + "Login: " + Credentials[1] + ", "
                    + "Serial: " + Credentials[3])

                smbConnect = SambaConnect(Credentials[1],Credentials[2],device,usbdirectory)

            if self.UsbUmount(device) != 0:
                Log(str(device.device_node) + ", failed umount")
                return None

            Log(str(device.device_node) + " umounted")

        if str(action) == "remove":
            pass

## Класс, выполняющий работу с Samba сервером и синхронизацию файлов
#
class SambaConnect:
    def __init__(self,Login,Password,device,usbdirectory):
        self.Login, self.Password, self.device, self.UsbDirectory = Login, Password, device, usbdirectory
        global config

        if not re.match('^[a-zA-Z0-9]*$', Login):
            Log("login contain unacceptable symbols: " + str(Login))
            return False

        self.UserDirectory = config["smb_mount_base_path"] + "/" + str(self.Login)

        if self.MakeDir(self.UserDirectory) == 0:
            Log("Directory for samba mount was created ")
        else:
            Log("Cannot create directory for samba mount")
            if getstatusoutput("/bin/ls " +  str(self.UserDirectory), True, timeout = 2)[0] == 0:
                Log("Directory for samba mount already existed")
            else:
                print(getstatusoutput("/bin/ls " +  str(self.UserDirectory), True, timeout = 2))
                Log("Something problems :(")
                return None

        if self.SmbMount() == 0:
            Log("Samba mounted for "+Login)
        else:
            Log("Trying umounted samba...")
            self.SmbUmount()

            if self.SmbMount() == 0:
                Log("Samba mounted for "+Login)
            else:
                Log("Cannot mount samba for "+Login)
                return None

        if self.Transfer():
            Log("Transfer for " + str(device.device_node) + " was executed" )
        else:
            Log("Transfer for" + str(device.device_node) + " was not executed" )

        if self.SmbUmount() == 0:
            Log("Samba umounted for "+Login)
        else:
            Log("Cannot umount samba for "+Login)
            return None

    ## Функцbя создания папки пользователя
    #
    # @param path - путь до папки
    # @param self - Возвратный указатель
    #
    def MakeDir(self,path):
        return getstatusoutput("/bin/mkdir '" + str(path) + "'", True, timeout = 2)[0]

    ## Функцbя создания папки пользователя
    #
    # @param path - путь до папки
    # @param self - Возвратный указатель
    #
    def RemoveDir(self,path):
        return getstatusoutput("/bin/rm -R '" + str(path) + "'", True, timeout = 2)[0]

    ## Функция монтирования каталога Samba
    #
    # @param self - Возвратный указатель
    #
    def SmbMount(self):
        command = ["/sbin/sudo /sbin/mount.cifs ", "//",config['server_ip'],"/", self.Login, " ", self.UserDirectory,
                " -o user=", self.Login, ",password=", self.Password,",workgroup=",config['workgroup'],
                ",rw,gid=", config['smb_gid'], ",uid=", config['smb_uid']]

        return getstatusoutput(''.join(command), True, timeout=20)[0]

    ## Функция размонтирования каталога Samba
    #
    # @param self - Возвратный указатель
    #
    def SmbUmount(self):
        command = ["/sbin/sudo /bin/umount ", self.UserDirectory]
        return getstatusoutput(''.join(command), True, timeout=20)[0]

    ## Функция копирования файлов согласно списку
    #
    # @param OsWalkObj - список файлов и папок, сгенерированный os.walk()
    # @param DestDir - папка назначения
    #
    # @param self - Возвратный указатель
    #
    def Copy(self,OsWalkObj, StartDir, DestDir):
        for level in OsWalkObj:
            for directory in level[1]:
                if self.MakeDir(DestDir+"/"+level[0]+"/"+directory) == 0:
                    pass
                else:
                    Log("Can`t create directory "+DestDir+"/"+level[0]+"/"+directory)

            for filename in level[2]:
                oldFile = StartDir +"/" +level[0]+   "/" + filename
                newFile = DestDir + "/" +level[0]+   "/" + filename

                if self.FileCopy(oldFile, newFile) == 0:
                    if self.RemoveFile(oldFile) != 0:
                        Log(Log("Can`t remove file  "+oldFile))
                else:
                    Log("Can`t copy file  "+newFile)

    ## Функция копирования файла
    #
    # @param StartPath - путь к файлу, который копируется
    # @param DestPath - путь, куда будет скопирован файл
    #
    # @param self - Возвратный указатель
    #
    def FileCopy(self,StartPath,DestPath):
        command = ["/bin/cp '", StartPath, "' '", DestPath, "'"]
        return getstatusoutput(''.join(command), True, timeout=20)[0]

    ## Функция удаление файла
    #
    # @param path - путь к файлу, который удаляется
    #
    # @param self - Возвратный указатель
    #
    def RemoveFile(self,path):
        command = ["/bin/rm '", path, "'"]
        return getstatusoutput(''.join(command), True, timeout=20)[0]

    ## Функция обмена данными между флешкой и сетевым диском
    #
    # @param self - Возвратный указатель
    #
    def Transfer(self):
        Log("Start transering...")
        self.UsbFileListW = os.walk(self.UsbDirectory + "/out")
        self.UsbFileList = []
        for level in self.UsbFileListW:
            level = list(level)
            level[0] = level[0].replace(self.UsbDirectory + "/out",".")
            self.UsbFileList.append(level)

        self.SmbFileListW = os.walk(self.UserDirectory + "/out")
        self.SmbFileList = []
        for level in self.SmbFileListW:
            level = list(level)
            level[0] = level[0].replace(self.UserDirectory + "/out",".")
            self.SmbFileList.append(level)

        Log("List of out directory in USB: \n" )
        for level in self.UsbFileList:
            for filename in level[2]:
                Log(level[0] + "/" + filename,False)
        Log("",False)

        self.Copy(self.UsbFileList,self.UsbDirectory+"/out",self.UserDirectory + "/in")
        Log("",False)

        Log("List of out directory in SMB: \n" )
        for level in self.SmbFileList:
            for filename in level[2]:
                Log(level[0] + "/" + filename,False)
        Log("",False)

        self.Copy(self.SmbFileList,self.UserDirectory + "/out",self.UsbDirectory + "/in")
        Log("",False)


## Директор
#
# Создание потоков и управление общей работой программы
config_parser = configparser.ConfigParser()
config_parser.read('isofc-service.conf')
config = config_parser['isofc']
Log("Isofc service is started")

# Создание объекта класса DeviceHandler
deviceHandler = DeviceHandler()
deviceHandler.start()

inp = ""
while(inp != "exit"):
    inp=str(input())

deviceHandler.ExitFlag = True # Задание флага ExitFlag значением True инициализирует выход
#sys.exit(0)
