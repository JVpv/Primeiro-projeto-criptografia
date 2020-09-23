# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'trabalho_criptografia.ui'
#
# Created by: PyQt5 UI code generator 5.13.2
#
# WARNING! All changes made in this file will be lost!

##################################################################################
#                                                                                #         
# Trabalho de Redes Convergentes - AV1.                                          #
#                                                                                #
# O trabalho consiste em uma interface gráfica, onde o usuário insere            #
# um texto, seleciona um dentre cinco algoritmos de criptografia, informa        #
# uma chave e é capaz tanto de cifrar o texto ou, caso ele já esteja             #
# cifrado, decriptá-lo. A interface foi feita usando o pyqt5 designer, e         #
# transformada em código por CLI.                                                #
#                                                                                #        
# Três dos algoritmos - Cifra de César, XOR e Simplified-DES - tiveram sua       #
# lógica implementada por mim, já o DES e o AES utilizam uma biblioteca.         #
# Todos os algoritmos estarão comentados para melhor compreensão do que          #
# foi feito.                                                                     #
#                                                                                #
# Funções comuns:                                                                #
# bin(c): converte c para binário. Exemplo: bin(2) = 0b10                        #
#                                                                                #
# bin(c)[x:]: converte c para binário E remove os x primeiros                    #
# caracteres. Exemplo: bin(2)[2:] = 10                                           #
#                                                                                #
# ord(c): converte c para o seu número representante em unicode.                 #
# Exemplo: ord(A) = 65                                                           #
#                                                                                #
# chr(c): converte o número unicode c para seu caractere representante.          #
# Exemplo: chr(97) = a                                                           #
#                                                                                #
# José Vítor Prado Varela - 1610362                                              #
#                                                                                #
##################################################################################

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QKeySequence
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import tkinter as tk
import os
from tkinter.filedialog import askopenfilename
import json
import base64
from base64 import b64encode, b64decode

class Ui_MainWindow(object):

    cifraSelecionada = ""
    k = 0
    tag = ""
    nonce = ""
    iv = ""
    json_input = ""

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("Trabalho AV1 Redes Convergentes")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.plainTxtBox = QtWidgets.QTextEdit(self.centralwidget)
        self.plainTxtBox.setGeometry(QtCore.QRect(10, 20, 381, 341))
        self.plainTxtBox.setObjectName("plainTxtBox")
        self.cryptTxtBox = QtWidgets.QTextBrowser(self.centralwidget)
        self.cryptTxtBox.setGeometry(QtCore.QRect(410, 20, 381, 341))
        self.cryptTxtBox.setObjectName("cryptTxtBox")
        self.chaveTxtBox = QtWidgets.QLineEdit(self.centralwidget)
        self.chaveTxtBox.setGeometry(QtCore.QRect(400, 380, 91, 31))
        self.chaveTxtBox.setObjectName("chaveTxtBox")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(400, 420, 93, 28))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.clickedCifrar)
        self.decodificarBtn = QtWidgets.QPushButton(self.centralwidget)
        self.decodificarBtn.setGeometry(QtCore.QRect(400, 460, 93, 28))
        self.decodificarBtn.setObjectName("decodificarBtn")
        self.decodificarBtn.clicked.connect(self.clickedDecodificar)
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(10, 370, 381, 171))
        self.groupBox.setObjectName("groupBox")
        self.cesarBtn = QtWidgets.QRadioButton(self.groupBox)
        self.cesarBtn.setGeometry(QtCore.QRect(10, 20, 111, 20))
        self.cesarBtn.setObjectName("cesarBtn")
        self.xorBtn = QtWidgets.QRadioButton(self.groupBox)
        self.xorBtn.setGeometry(QtCore.QRect(10, 50, 95, 20))
        self.xorBtn.setObjectName("xorBtn")
        self.sdesBtn = QtWidgets.QRadioButton(self.groupBox)
        self.sdesBtn.setGeometry(QtCore.QRect(10, 80, 95, 20))
        self.sdesBtn.setObjectName("sdesBtn")
        self.desBtn = QtWidgets.QRadioButton(self.groupBox)
        self.desBtn.setGeometry(QtCore.QRect(10, 110, 95, 20))
        self.desBtn.setObjectName("desBtn")
        self.aesBtn = QtWidgets.QRadioButton(self.groupBox)
        self.aesBtn.setGeometry(QtCore.QRect(10, 140, 95, 20))
        self.aesBtn.setObjectName("aesBtn")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 26))
        self.menubar.setObjectName("menubar")
        self.menuArquivo = QtWidgets.QMenu(self.menubar)
        self.menuArquivo.setObjectName("menuArquivo")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionSalvar = QtWidgets.QAction(MainWindow)
        self.actionSalvar.setObjectName("actionSalvar")
        self.actionAbrir = QtWidgets.QAction(MainWindow)
        self.actionAbrir.setObjectName("actionAbrir")
        self.actionLimpar = QtWidgets.QAction(MainWindow)
        self.actionLimpar.setObjectName("actionLimpar")
        self.menuArquivo.addSeparator()
        self.menuArquivo.addAction(self.actionSalvar)
        self.menuArquivo.addAction(self.actionAbrir)
        self.menuArquivo.addAction(self.actionLimpar)
        self.actionLimpar.triggered.connect(self.clickedLimpar)
        self.actionAbrir.triggered.connect(self.clickedAbrir)
        self.actionAbrir.setShortcut(QKeySequence('Ctrl+O'))
        self.actionSalvar.triggered.connect(self.clickedSalvar)
        self.actionSalvar.setShortcut(QKeySequence('Ctrl+S'))
        self.menubar.addAction(self.menuArquivo.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
    
    # A função abaixo é chamada quando o usuário clica no botão "Cifrar".
    # Ela irá checar qual dos RadioButtons está selecionado e aplicar sua
    # cifra correspondente utilizando a chave informada pelo usuário.
    def clickedCifrar(self):
        textoCifrado = "" #Texto resultante.
        self.k = int(self.chaveTxtBox.text()) # Chave informada pelo usuário.
        
        # Cifra de César
        if self.cesarBtn.isChecked():
            for i in range(len(self.plainTxtBox.toPlainText())):
                j = self.plainTxtBox.toPlainText()[i]
                # Simplesmente avança k caracteres na tabela ascii.
                textoCifrado += chr(ord(j) + self.k)
        
        # XOR
        if self.xorBtn.isChecked():
            for i in range(len(self.plainTxtBox.toPlainText())):
                j = self.plainTxtBox.toPlainText()[i]
                # ^ em python = xor. Essa é a criptografia mais simples
                # de se codar, apesar de ser bem mais eficiente que césar.
                textoCifrado += chr(ord(j)^self.k)
        
        # Simplified-DES
        if self.sdesBtn.isChecked():
            # Primeiro transforma k em uma chave de 10 bits
            self.k = bin(int(self.chaveTxtBox.text()))[2:]
            self.k = '0000000000'[len(self.k):]+self.k
            key = self.k

            # Segundo, aplica P10 no vetor key.
            key = key[2]+key[4]+key[1]+key[6]+key[3]+key[9]+key[0]+key[8]+key[7]+key[5]
            # Terceiro, Left-Shift 1 nos 5 primeiros bits e nos 5 últimos.
            key = key[1]+key[2]+key[3]+key[4]+key[0]+key[6]+key[7]+key[8]+key[9]+key[5]
            # Quarto, aplica P8, que também remove os dois primeiros bits.
            # Assim, adquirimos a primeira chave, k1.
            k1 = key[5]+key[2]+key[6]+key[3]+key[7]+key[4]+key[9]+key[8]
            # OBS: é importante deixar k1 com um nome diferente, pois precisaremos do vetor
            # key que encontramos após o LS1 para descobrir a segunda chave (k2).
            # Para descobrir k2, usamos Left-Shift 2 no vetor key.
            key =key[2]+key[3]+key[4]+key[0]+key[1]+key[7]+key[8]+key[9]+key[5]+key[6]
            # E finalmente, reaplica-se P8 para encontrar k2.
            k2 = key[5]+key[2]+key[6]+key[3]+key[7]+key[4]+key[9]+key[8]

            # Agora que temos k1 e k2 terminamos a parte fácil.
            # Primeiramente, um loop para repetir o processo de criptografia em cada caractere.
            # Além disso, o caractere é convertido para um número binário de 8 bits.
            for i in range(len(self.plainTxtBox.toPlainText())):
                textArr ='{0:08b}'.format(ord(self.plainTxtBox.toPlainText()[i]))
    
                # Então, aplica-se a permutação inicial no caractere.
                textArr = textArr[1]+textArr[5]+textArr[2]+textArr[0]+textArr[3]+textArr[7]+textArr[4]+textArr[6]
    
                # Agora a parte mais complicada: a função fk, que consiste em uma combinação de
                # funções de permutação e substituição.
                # Primeiro: a operação de permutação e extensão, onde separa-se os 4 primeiros bits
                # do caractere dos 4 últimos, e aplica-se essa operação nos 4 últimos para transformá-los
                # em 8 bits, e guarde os 4 primeiros bits originais, que não foram permutados.
                ep_Original = textArr[7]+textArr[4]+textArr[5]+textArr[6]+textArr[5]+textArr[6]+textArr[7]+textArr[4]
                xorEp = textArr[0]+textArr[1]+textArr[2]+textArr[3]
    
                # Segundo: aplica-se XOR nos bits permutados e extendidos, que chamaremos de ep, com
                # a chave k1 calculada mais cedo.
                ep = '{0:08b}'.format(int(ep_Original,2)^int(k1,2))

                # Agora, é feito o mapeamento S0 e S1. S0 e S1 são duas tabelas que ditam qual a
                # combinação de 4 bits que será concedida a esses 8 bits ep após o xor. Para isso, 
                # separaremos em dois grupos de 4 bits, o primeiro mapeará S0 e o segundo mapeará S1.
                # O primeiro e o último bit de cada grupo, juntos, resultará em um número de 0 a 3, que
                # identificará a linha da matriz, e o segundo e o terceiro bit, juntos, identificarão a
                # coluna.
                ep_s0 = ep[0]+ep[1]+ep[2]+ep[3]
                ep_s1 = ep[4]+ep[5]+ep[6]+ep[7]
    
                S0_Matrix = [["01", "00", "11", "10"], ["11", "10", "01", "00"], ["00", "10", "01", "11"], ["11", "01", "11", "10"]]
                S1_Matrix = [["00", "01", "10", "11"], ["10", "00", "01", "11"], ["11", "00", "01", "00"], ["10", "01", "00", "11"]]

                ep_s0 = [int(ep_s0[0]+ep_s0[3],2), int(ep_s0[1]+ep_s0[2],2)]
                ep_s1 = [int(ep_s1[0]+ep_s1[3],2), int(ep_s1[1]+ep_s1[2],2)]

                ep_s0 = S0_Matrix[ep_s0[0]][ep_s0[1]]
                ep_s1 = S1_Matrix[ep_s1[0]][ep_s1[1]]

                # Assim, após o mapeamento, ep se torna um número binário de 4 bits.
                ep = ep_s0+ep_s1
    
                # No próximo passo, é feita a permutação P4 em ep.
                ep = ep[1]+ep[3]+ep[2]+ep[0]

                # Lembra dos 4 primeiros bits originais? Usaremo-nos agora para aplicar
                # xor com os 4 bits permutados e mapeados de ep.
                ep = '{0:04b}'.format(int(ep,2)^int(xorEp,2))

                # Agora pegamos os 4 últimos bits ORIGINAIS, ou seja, após a permutação inicial, e 
                # invertemos com os 4 bits permutados, mapeados e após aplicado o xor, e então juntamos
                # todos os 8 em um único número.
                textArr = textArr[4]+textArr[5]+textArr[6]+textArr[7]+ep

                # E então... Repetimos todo o processo, como se esse novo vetor fosse a permutação inicial,
                # mas dessa vez usaremos a chave k2 após a extensão e permutação.
                ep_Original = textArr[7]+textArr[4]+textArr[5]+textArr[6]+textArr[5]+textArr[6]+textArr[7]+textArr[4]
                xorEp = textArr[0]+textArr[1]+textArr[2]+textArr[3]
    
                # XOR no ep
                ep = '{0:08b}'.format(int(ep_Original,2)^int(k2,2))

                # S0 e S1
                ep_s0 = ep[0]+ep[1]+ep[2]+ep[3]
                ep_s1 = ep[4]+ep[5]+ep[6]+ep[7]

                ep_s0 = [int(ep_s0[0]+ep_s0[3],2), int(ep_s0[1]+ep_s0[2],2)]
                ep_s1 = [int(ep_s1[0]+ep_s1[3],2), int(ep_s1[1]+ep_s1[2],2)]

                ep_s0 = S0_Matrix[ep_s0[0]][ep_s0[1]]
                ep_s1 = S1_Matrix[ep_s1[0]][ep_s1[1]]

                ep = ep_s0+ep_s1
    
                # P4 com o resultado
                ep = ep[1]+ep[3]+ep[2]+ep[0]

                # XOR com os bits restantes
                ep = '{0:04b}'.format(int(ep,2)^int(xorEp,2))

                # Junta aos bits originais, mas dessa vez sem inverter a ordem dos bits
                chrCifrado = ep+textArr[4]+textArr[5]+textArr[6]+textArr[7]
    
                # Agora aplicamos a permutação inversa
                chrCifrado = chrCifrado[3]+chrCifrado[0]+chrCifrado[2]+chrCifrado[4]+chrCifrado[6]+chrCifrado[1]+chrCifrado[7]+chrCifrado[5]
                
                # E finalmente, adicionamos esse caractere ao texto cifrado.
                textoCifrado += chr(int(chrCifrado,2))

        if self.desBtn.isChecked():
            # Sem comentários no DES e no AES, visto que ambos utilizam de uma biblioteca.
            self.k = int(self.chaveTxtBox.text()).to_bytes(8, byteorder='little')            
            cipher = DES.new(self.k, DES.MODE_CBC)
            self.iv = b64encode(cipher.iv).decode('latin-1')
            textoCifrado = cipher.encrypt(pad(self.plainTxtBox.toPlainText().encode('latin-1'), DES.block_size))
            textoCifrado = b64encode(textoCifrado).decode('latin-1')
            self.json_input = json.dumps({'iv':self.iv, 'ciphertext':textoCifrado})
            textoCifrado = self.iv+textoCifrado


        if self.aesBtn.isChecked():
            self.k = int(self.chaveTxtBox.text()).to_bytes(8, byteorder='little')            
            cipher = DES.new(self.k, AES.MODE_CBC)
            self.iv = b64encode(cipher.iv).decode('latin-1')
            textoCifrado = cipher.encrypt(pad(self.plainTxtBox.toPlainText().encode('latin-1'), DES.block_size))
            textoCifrado = b64encode(textoCifrado).decode('latin-1')
            self.json_input = json.dumps({'iv':self.iv, 'ciphertext':textoCifrado})
            textoCifrado = self.iv+textoCifrado

        self.cryptTxtBox.setText(textoCifrado)


    # A função abaixo é chamada quando o usuário clica no botão Decodificar.
    # Ela checa qual dos RadioButtons está selecionado e decripta o texto
    # fazendo o processo inverso à criptografia utilizando a chave informada.
    def clickedDecodificar(self):
        textoPlano = "" # Texto resultante
        self.k = int(self.chaveTxtBox.text()) # Chave informada pelo usuário.

        # Cifra de César
        if self.cesarBtn.isChecked():
            for i in range(len(self.plainTxtBox.toPlainText())):
                j = self.plainTxtBox.toPlainText()[i]
                # Para cifrar, avançamos k posições, portanto, para
                # decriptar, voltamos k posições.
                textoPlano += chr(ord(j) - self.k)

        # XOR        
        if self.xorBtn.isChecked():
            for i in range(len(self.plainTxtBox.toPlainText())):
                j = self.plainTxtBox.toPlainText()[i]
                # É o mesmo comando tanto para cifrar quanto para decriptar.
                textoPlano += chr(ord(j)^self.k)
        
        if self.sdesBtn.isChecked():
            # O processo para geração das chaves é igual ao da cifra.
            self.k = bin(int(self.chaveTxtBox.text()))[2:]
            self.k = '0000000000'[len(self.k):]+self.k
            key = self.k
            key = key[2]+key[4]+key[1]+key[6]+key[3]+key[9]+key[0]+key[8]+key[7]+key[5]
            key = key[1]+key[2]+key[3]+key[4]+key[0]+key[6]+key[7]+key[8]+key[9]+key[5]
            k1 = key[5]+key[2]+key[6]+key[3]+key[7]+key[4]+key[9]+key[8]
            key =key[2]+key[3]+key[4]+key[0]+key[1]+key[7]+key[8]+key[9]+key[5]+key[6]
            k2 = key[5]+key[2]+key[6]+key[3]+key[7]+key[4]+key[9]+key[8]

            # Agora é feito um processo quase igual ao de criptografia, porém dessa vez as funções fk são
            # trocadas, isto é, fazemos primeiro fk2, depois swap e finalmente fk1.
            for i in range(len(self.plainTxtBox.toPlainText())):
                textArr ='{0:08b}'.format(ord(self.plainTxtBox.toPlainText()[i]))
            
                # IP
                textArr = textArr[1]+textArr[5]+textArr[2]+textArr[0]+textArr[3]+textArr[7]+textArr[4]+textArr[6]
    
                #FK2
                ep_Original = textArr[7]+textArr[4]+textArr[5]+textArr[6]+textArr[5]+textArr[6]+textArr[7]+textArr[4]
                xorEp = textArr[0]+textArr[1]+textArr[2]+textArr[3]
    
                ep = '{0:08b}'.format(int(ep_Original,2)^int(k2,2))

                ep_s0 = ep[0]+ep[1]+ep[2]+ep[3]
                ep_s1 = ep[4]+ep[5]+ep[6]+ep[7]
    
                S0_Matrix = [["01", "00", "11", "10"], ["11", "10", "01", "00"], ["00", "10", "01", "11"], ["11", "01", "11", "10"]]
                S1_Matrix = [["00", "01", "10", "11"], ["10", "00", "01", "11"], ["11", "00", "01", "00"], ["10", "01", "00", "11"]]

                ep_s0 = [int(ep_s0[0]+ep_s0[3],2), int(ep_s0[1]+ep_s0[2],2)]
                ep_s1 = [int(ep_s1[0]+ep_s1[3],2), int(ep_s1[1]+ep_s1[2],2)]

                ep_s0 = S0_Matrix[ep_s0[0]][ep_s0[1]]
                ep_s1 = S1_Matrix[ep_s1[0]][ep_s1[1]]

                ep = ep_s0+ep_s1
    
                ep = ep[1]+ep[3]+ep[2]+ep[0]

                ep = '{0:04b}'.format(int(ep,2)^int(xorEp,2))

                textArr = textArr[4]+textArr[5]+textArr[6]+textArr[7]+ep

                #FK1
                ep_Original = textArr[7]+textArr[4]+textArr[5]+textArr[6]+textArr[5]+textArr[6]+textArr[7]+textArr[4]
                xorEp = textArr[0]+textArr[1]+textArr[2]+textArr[3]
    
                ep = '{0:08b}'.format(int(ep_Original,2)^int(k1,2))

                ep_s0 = ep[0]+ep[1]+ep[2]+ep[3]
                ep_s1 = ep[4]+ep[5]+ep[6]+ep[7]

                ep_s0 = [int(ep_s0[0]+ep_s0[3],2), int(ep_s0[1]+ep_s0[2],2)]
                ep_s1 = [int(ep_s1[0]+ep_s1[3],2), int(ep_s1[1]+ep_s1[2],2)]

                ep_s0 = S0_Matrix[ep_s0[0]][ep_s0[1]]
                ep_s1 = S1_Matrix[ep_s1[0]][ep_s1[1]]

                ep = ep_s0+ep_s1
    
                ep = ep[1]+ep[3]+ep[2]+ep[0]

                ep = '{0:04b}'.format(int(ep,2)^int(xorEp,2))

                chrDecriptado = ep+textArr[4]+textArr[5]+textArr[6]+textArr[7]
    
                # IP^-1
                chrDecriptado = chrDecriptado[3]+chrDecriptado[0]+chrDecriptado[2]+chrDecriptado[4]+chrDecriptado[6]+chrDecriptado[1]+chrDecriptado[7]+chrDecriptado[5]
                
                # Adição do caractere.
                textoPlano += chr(int(chrDecriptado,2))

        if self.desBtn.isChecked():
            self.k = int(self.chaveTxtBox.text()).to_bytes(8, byteorder='little')
            try:
                b64 = json.loads(self.json_input)
                self.iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = DES.new(self.k, DES.MODE_CBC, self.iv)
                textoPlano = unpad(cipher.decrypt(ct), DES.block_size).decode('latin-1')
            except ValueError as ve:
                print(ve)

        if self.aesBtn.isChecked():
            self.k = int(self.chaveTxtBox.text()).to_bytes(8, byteorder='little')
            try:
                b64 = json.loads(self.json_input)
                self.iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = DES.new(self.k, AES.MODE_CBC, self.iv)
                textoPlano = unpad(cipher.decrypt(ct), AES.block_size).decode('latin-1')
            except ValueError as ve:
                print(ve)

        self.cryptTxtBox.setText(textoPlano)


    # Essa função é chamada quando o usuário seleciona Arquivo -> Abrir.
    # Ela permite que o usuário abra um arquivo já existente.
    def clickedAbrir(self):
        root = tk.Tk()
        root.withdraw()
        filepath = askopenfilename(initialdir="/", title = "Selecione o arquivo", filetypes=(("Arquivos de Texto", "*.txt"), ("Todos os Arquivos", "*.*")))
        try:
            with open(filepath, "rb") as f:
                self.plainTxtBox.setText(f.read().decode('latin-1'))                   
        except IOError:
            print("Algo deu errado")

    def clickedSalvar(self):
        text = "TEXTO DE INPUT: " + self.plainTxtBox.toPlainText() + "\n\n" + "CHAVE: " + self.chaveTxtBox.text() + "\n\n" + "TEXTO DE OUTPUT: " + self.cryptTxtBox.toPlainText()
        fileName = "ARQUIVO_CIFRADO.txt"
        myFile = open(fileName, 'w')
        myFile.write(text)
        myFile.close()

        os.startfile(fileName)
    
    # Essa função é chamada quando o usuário seleciona Arquivo -> Limpar. Ela
    # retorna o programa para o estado inicial.
    def clickedLimpar(self):
        self.cryptTxtBox.setText("")
        self.chaveTxtBox.setText("")
        self.plainTxtBox.setText("")
        self.sdesBtn.setChecked(False)
        self.aesBtn.setChecked(False)
        self.desBtn.setChecked(False)
        self.xorBtn.setChecked(False)
        self.cesarBtn.setChecked(True)


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Trabalho AV1 Redes Convergentes"))
        self.plainTxtBox.setPlaceholderText(_translate("MainWindow", "Digite aqui o texto a ser cifrado/descriptografado"))
        self.cryptTxtBox.setPlaceholderText(_translate("MainWindow", "Texto cifrado/descriptografado"))
        self.chaveTxtBox.setPlaceholderText(_translate("MainWindow", "Chave"))
        self.pushButton.setText(_translate("MainWindow", "Cifrar"))
        self.decodificarBtn.setText(_translate("MainWindow", "Decodificar"))
        self.groupBox.setTitle(_translate("MainWindow", "Cifras:"))
        self.cesarBtn.setText(_translate("MainWindow", "Cifra de César"))
        self.xorBtn.setText(_translate("MainWindow", "XOR"))
        self.sdesBtn.setText(_translate("MainWindow", "SDES"))
        self.desBtn.setText(_translate("MainWindow", "DES"))
        self.aesBtn.setText(_translate("MainWindow", "AES"))
        self.menuArquivo.setTitle(_translate("MainWindow", "Arquivo"))
        self.actionSalvar.setText(_translate("MainWindow", "Salvar"))
        self.actionAbrir.setText(_translate("MainWindow", "Abrir"))
        self.actionLimpar.setText(_translate("MainWindow", "Limpar"))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
