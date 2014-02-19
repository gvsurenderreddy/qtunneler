#!/bin/env python3
"""
Copyright (C) 2014 by Yichao Zhou <broken.zhou AT gmail DOT com>
License: http://www.gnu.org/licenses/gpl.html GPL version 3 or higher

Any comments are welcome through email and github!
"""

import codecs
import re
import random
import os
import pexpect
import sys
import string
import time
from PyQt4 import QtGui
from PyQt4 import QtCore
from PyQt4.QtCore import Qt, pyqtSignal

try:
    from PyQt4.QtCore import QString
except ImportError:
    QString = str

RETRY_DELAY = [ 5, 5, 10, 20, 60 ]

STATE_NOTCONNECTED = 0
STATE_CONNECTING = 1
STATE_CONNECTED = 2

class SSHThread(QtCore.QThread):
    # signal
    messageLogged = pyqtSignal(QString)
    stateSwitched = pyqtSignal(int)
    portOccupied  = pyqtSignal()

    answerCondition = QtCore.QWaitCondition()

    SSH_UNKNOWN = 0
    SSH_FAIL = 1
    SSH_EXIT = 2
    SSH_OK = 3
    SSH_RETRY = 4

    def __init__(self, app):
        super(SSHThread, self).__init__()
        self.app = app
        self.retryCount = 0

    def log(self, msg):
        self.messageLogged.emit(msg)

    def switchState(self, state):
        self.stateSwitched.emit(state)

    def wait(self, timeout=30):
        """Try to establish a connection and return current status

        Args:
            timeout:         set the timeout of pexpect

        Returns:
            SSH_OK:         This connection is successful.
            SSH_FAIL:       Connection failed due to some reason, retry.
            SSH_EXIT:       Fatal error or user teminated the process.
                            Thread should exit now.
            SSH_UNKNOWN:    SSH does not return enough information
        """
        index = self.ssh.expect([
            pexpect.TIMEOUT,                    #0
            "ssh: connect to host",             #1
            "Permission denied (publickey)",    #2
            "The authenticity of host",         #3
            "s password: ",                     #4
            pexpect.EOF,                        #5
            "execing",                          #6
            "connection ok",                    #7
            "restarting ssh",                   #8
            "channel_setup_fwd_listener: cannot listen to port", #9
            "Address already in use",           #10
        ], timeout=timeout)

        if index == 0:
            # Nothing happenes
            return self.SSH_UNKNOWN
        elif index == 1:
            return self.SSH_FAIL
        elif index == 2:
            self.log("Permission denied; Is your private key correct?")
            return self.SSH_EXIT
        elif index == 3:
            # We need to prompt the user to accept the server's fingerprint
            self.log("Please check server's fingerprint")
            self.ssh.sendline("yes")
            return self.wait(timeout=timeout)
        elif index == 4:
            # Send password
            return self.sendPassword(timeout=timeout)
        elif index == 5:
            # Process terminated
            self.log("Process terminated")
            return self.SSH_EXIT
        elif index == 6:
            self.log("Connecting...")
            return self.SSH_UNKNOWN
        elif index == 7:
            # connection ok
            return self.SSH_OK
        elif index == 8:
            self.log("Connection is down. Please wait for reconnecting")
            return self.SSH_FAIL
        elif index == 9:
            portNumber = self.app.socksPortEdit.text();
            self.log("Cannot listen SOCKS5 port at {}".format(portNumber))
            return self.SSH_EXIT
        elif index == 10:
            portNumber = self.app.monitorPort
            self.log("Bad luck: monitor port is already in use".format(portNumber))
            self.app.chooseMonitorPort()
            return self.SSH_RETRY

    def sendPassword(self, timeout):
        self.ssh.sendline(self.app.passphraseLineEdit.text())
        self.log("Password is sent")
        index = self.ssh.expect([
            pexpect.TIMEOUT,                    #0
            "Permission denied",                #1
            "ssh: connect to host",             #2
            pexpect.EOF,                        #3
            "connection ok",                    #4
        ], timeout=timeout)
        if index == 0:
            return self.SSH_UNKNOWN
        elif index == 1:
            self.log("Permission denied; Is your password correct?")
            self.app.disconnect()
            return self.SSH_EXIT
        elif index == 2:
            return self.SSH_FAIL
        elif index == 3:
            self.log("Process terminated")
            return self.SSH_EXIT
        elif index == 4:
            return self.SSH_OK

    def checkState(self, result):
        """Check the result of wait(), and handle it.

        Returns:
            True:   if this thread should exit
            False:  otherwise
        """

        if result == self.SSH_OK:
            self.switchState(STATE_CONNECTED)
            return False
        elif result == self.SSH_EXIT:
            self.switchState(STATE_NOTCONNECTED)
            self.app.disconnect()
            return True
        elif result == self.SSH_UNKNOWN:
            return False;
        elif result == self.SSH_FAIL:
            # SSH_FAIL: Retry
            self.switchState(STATE_CONNECTING)
            return False
        elif result == self.SSH_RETRY:
            self.connect()
            return False

    def connect(self):
        self.app.disconnect()
        self.switchState(STATE_CONNECTING)

        command = self.app.getSSHCommand()
        env = self.app.getSSHEnv()

        self.log(command)
        self.ssh = pexpect.spawn(command, env=env)

    def disconnect(self):
        while hasattr(self, 'ssh') and not self.ssh.terminate(force=True):
            pass
        self.switchState(STATE_NOTCONNECTED)

    def run(self):
        self.connect()

        first = True
        while True:
            state = self.wait(timeout=15)
            if self.checkState(state):
                return
            if state == self.SSH_FAIL:
                first = True
            if state == self.SSH_OK and first:
                first = False
                self.log("Connection is established")

class QTunneler(QtGui.QWidget):
    def __init__(self):
        super(QTunneler, self).__init__()

        self.initUI()
        self.sshThread = SSHThread(self)
        self.state = STATE_NOTCONNECTED
        self.loadConfig()

        self.sshThread.messageLogged.connect(self.log)
        self.sshThread.stateSwitched.connect(self.switchState)

        self.autoStartup.stateChanged.connect(self.saveConfig)
        self.autoConnect.stateChanged.connect(self.saveConfig)
        self.usingPolipo.stateChanged.connect(self.saveConfig)
        self.remeberPassowrd.stateChanged.connect(self.saveConfig)
        self.promptOnExit.stateChanged.connect(self.saveConfig)

    def initUI(self): #{{{
        expandingPolicy = QtGui.QSizePolicy.Expanding

        vertical = QtGui.QVBoxLayout()

        editLayout = QtGui.QGridLayout()
        vertical.addLayout(editLayout)

        # editLayout.setSpacing(5)
        self.serverAddressLabel = QtGui.QLabel("Server Address:")
        self.serverAddressLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.serverAddressLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.serverAddressLineEdit = QtGui.QLineEdit()
        editLayout.addWidget(self.serverAddressLabel, 0, 0)
        editLayout.addWidget(self.serverAddressLineEdit, 0, 1)

        self.serverPortLabel = QtGui.QLabel("Server Port:")
        self.serverPortLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.serverPortLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.serverPortLineEdit = QtGui.QLineEdit()
        editLayout.addWidget(self.serverPortLabel, 0, 2)
        editLayout.addWidget(self.serverPortLineEdit, 0, 3)
        
        self.usernameLabel = QtGui.QLabel("Username:")
        self.usernameLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.usernameLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.usernameLineEdit = QtGui.QLineEdit()
        editLayout.addWidget(self.usernameLabel, 1, 0)
        editLayout.addWidget(self.usernameLineEdit, 1, 1)

        self.passphraseLabel = QtGui.QLabel("Passphrase:")
        self.passphraseLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.passphraseLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.passphraseLineEdit = QtGui.QLineEdit()
        self.passphraseLineEdit.setEchoMode(QtGui.QLineEdit.Password)
        editLayout.addWidget(self.passphraseLabel, 1, 2)
        editLayout.addWidget(self.passphraseLineEdit, 1, 3)

        self.socksPortLabel = QtGui.QLabel("SOCKS5 Proxy Port:")
        self.socksPortLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.socksPortLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.socksPortEdit = QtGui.QLineEdit("7070")
        editLayout.addWidget(self.socksPortLabel, 2, 0)
        editLayout.addWidget(self.socksPortEdit, 2, 1)

        self.httpPortLabel = QtGui.QLabel("HTTP Proxy Port:")
        self.httpPortLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.httpPortLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.httpPortEdit = QtGui.QLineEdit("8080")
        self.httpPortEdit.setEnabled(False);
        editLayout.addWidget(self.httpPortLabel, 2, 2)
        editLayout.addWidget(self.httpPortEdit, 2, 3)

        self.identityLabel = QtGui.QLabel("Identity File:")
        self.identityLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.identityLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.identityEdit = QtGui.QLineEdit()
        editLayout.addWidget(self.identityLabel, 3, 0)
        editLayout.addWidget(self.identityEdit, 3, 1, 1, 3)

        self.optionalLabel = QtGui.QLabel("Optional Arguments:")
        self.optionalLabel.setSizePolicy(expandingPolicy, expandingPolicy)
        self.optionalLabel.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self.optionalEdit = QtGui.QLineEdit()
        editLayout.addWidget(self.optionalLabel, 4, 0)
        editLayout.addWidget(self.optionalEdit, 4, 1, 1, 3)

        configurationLayout = QtGui.QGridLayout()
        vertical.addLayout(configurationLayout)
        self.autoStartup = QtGui.QCheckBox("Auto-startup")
        self.autoConnect = QtGui.QCheckBox("Auto-connect on Startup")
        self.usingPolipo = QtGui.QCheckBox("Using Polipo for HTTP Proxy")
        self.remeberPassowrd = QtGui.QCheckBox("Save Password")
        self.promptOnExit = QtGui.QCheckBox("Prompt on Exit")
        configurationLayout.addWidget(self.autoStartup, 0, 0)
        configurationLayout.addWidget(self.autoConnect, 0, 1)
        configurationLayout.addWidget(self.usingPolipo, 0, 2)
        configurationLayout.addWidget(self.remeberPassowrd, 1, 0)
        configurationLayout.addWidget(self.promptOnExit, 1, 1)

        self.usingPolipo.stateChanged.connect(self.httpPortEdit.setEnabled)

        self.historyList = QtGui.QTextEdit()
        self.historyList.setReadOnly(True)
        self.historyList.setFont(QtGui.QFont("monospace"))
        vertical.addWidget(self.historyList)

        buttonLayout = QtGui.QHBoxLayout()
        vertical.addLayout(buttonLayout)

        self.connectButton = QtGui.QPushButton("&Connect")
        self.connectButton.clicked.connect(self.connect)
        self.hideButton = QtGui.QPushButton("&Hide")
        self.hideButton.clicked.connect(self.minimize)
        self.exitButton = QtGui.QPushButton("&Exit")
        self.exitButton.clicked.connect(self.exit)
        self.aboutButton = QtGui.QPushButton("&About")
        self.aboutButton.clicked.connect(self.about)

        buttonLayout.addWidget(self.connectButton)
        buttonLayout.addWidget(self.hideButton)
        buttonLayout.addWidget(self.exitButton)
        buttonLayout.addWidget(self.aboutButton)

        self.setLayout(vertical)
        self.setWindowTitle("QTunneler - Not Connected")
        self.move(QtGui.QApplication.desktop().screen().rect().center() -
                  self.rect().center())

        self.show()
        self.passphraseLineEdit.setFocus()
        #}}}

    def closeEvent(self, event):
        self.disconnect()
        event.accept()

    def getSSHCommand(self):
        if not hasattr(self, "monitorPort"):
            self.chooseMonitorPort()
        command = "autossh -M {} -TnN".format(self.monitorPort)
        command += " -D {}".format(self.socksPortEdit.text())
        if self.identityEdit.text().strip() != "":
            command += " -i {}".format(self.identityEdit.text())
        command += " {}@{}".format(self.usernameLineEdit.text(),
                                   self.serverAddressLineEdit.text())
        return command

    def getSSHEnv(self):
        return {
            "AUTOSSH_DEBUG" : "1",
            "AUTOSSH_FIRST_POLL" : "10",
            "AUTOSSH_GATETIME" : "0",
            "AUTOSSH_POLL" : "30",
        }

    def connect(self):
        if self.state in [STATE_CONNECTING , STATE_CONNECTED]:
            self.disconnect()
            return
        self.saveConfig()
        self.sshThread.start()

    def disconnect(self):
        self.sshThread.disconnect()

    def minimize(self):
        pass

    def exit(self):
        self.close()
        pass

    def about(self):
        pass

    def log(self, message):
        logstr = time.strftime("<b>[%B %d, %H:%M:%S]</b> ")
        logstr += message
        self.historyList.append(logstr)

    def switchState(self, state):
        self.state = state
        if state == STATE_NOTCONNECTED:
            stateStr = "Not Connected"
            self.connectButton.setText("Connect")
        elif state == STATE_CONNECTING:
            stateStr = "Connecting"
            self.connectButton.setText("Disconnect")
        else:
            stateStr = "Connected"
            self.connectButton.setText("Disconnect")
        self.setWindowTitle("QTunneler - {}".format(stateStr))

    def chooseMonitorPort(self):
        self.monitorPort = random.randint(10000, 32767)
        self.saveConfig()

    def loadConfig(self):
        setting = QtCore.QSettings("qtunneler")

        self.serverAddressLineEdit.setText(setting.value("ServerAddress", "your.sshserver.com", type=QString))
        self.serverPortLineEdit.setText(setting.value("ServerPort", "22", type=QString))
        self.usernameLineEdit.setText(setting.value("Username", "username", type=QString))
        self.passphraseLineEdit.setText(codecs.encode(setting.value("Passphrase", "", type=QString), "rot_13"))
        self.socksPortEdit.setText(setting.value("SocksPort", "7070", type=QString))
        self.httpPortEdit.setText(setting.value("HttpPort", "8080", type=QString))
        self.identityEdit.setText(setting.value("Identity", "", type=QString))
        self.optionalEdit.setText(setting.value("Optional", "", type=QString))
        self.autoStartup.setCheckState(setting.value("AutoStartup", Qt.Unchecked, type=Qt.CheckState))
        self.autoConnect.setCheckState(setting.value("AutoConnect", Qt.Unchecked, type=Qt.CheckState))
        self.usingPolipo.setCheckState(setting.value("UsingPolipo", Qt.Unchecked, type=Qt.CheckState))
        self.remeberPassowrd.setCheckState(setting.value("RememberPassword", Qt.Unchecked, type=Qt.CheckState))
        self.promptOnExit.setCheckState(setting.value("PromptOnExit", Qt.Checked, type=Qt.CheckState))

    def saveConfig(self):
        setting = QtCore.QSettings("qtunneler")

        setting.setValue("ServerAddress", self.serverAddressLineEdit.text())
        setting.setValue("ServerPort", self.serverPortLineEdit.text())
        setting.setValue("Username", self.usernameLineEdit.text())
        password = ""
        if self.remeberPassowrd.checkState():
            password = codecs.encode(self.passphraseLineEdit.text(), "rot_13")
        setting.setValue("Passphrase", password)
        setting.setValue("SocksPort", self.socksPortEdit.text())
        setting.setValue("HttpPort", self.httpPortEdit.text())
        setting.setValue("Identity", self.identityEdit.text())
        setting.setValue("Optional", self.optionalEdit.text())

        setting.setValue("AutoStartup", self.autoStartup.checkState())
        setting.setValue("AutoConnect", self.autoConnect.checkState())
        setting.setValue("UsingPolipo", self.usingPolipo.checkState())
        setting.setValue("RememberPassword", self.remeberPassowrd.checkState())
        setting.setValue("PromptOnExit", self.promptOnExit.checkState())

def main():
    app = QtGui.QApplication(sys.argv)
    tunner = QTunneler()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
