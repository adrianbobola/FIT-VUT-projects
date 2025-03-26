import numpy as np
import matplotlib.pyplot as plt
import soundfile as sf
import scipy as sp
from scipy.io import wavfile
import cmath
from scipy.signal import spectrogram, lfilter
# -----------------------------------------------------------------------
# ------------ UKOL 1  --------------------------------------------------
# -----------------------------------------------------------------------
fs1, nahravka1 = wavfile.read('../audio/maskoff_tone.wav')

fs2, nahravka2 = wavfile.read('../audio/maskon_tone.wav')

# -----------------------------------------------------------------------
# ------------ UKOL 2 ---------------------------------------------------
# -----------------------------------------------------------------------

fs3, nahravka3 = wavfile.read('../audio/maskoff_sentence.wav')
nahravka3 = nahravka3[1000:len(nahravka3)] # posun kvôli maskon začiatku
t8 = (np.arange(len(nahravka3)))

fs4, nahravka4 = wavfile.read('../audio/maskon_sentence.wav')
t9 = (np.arange(len(nahravka4)))

# -----------------------------------------------------------------------
# ------------ UKOL 3 ---------------------------------------------------
# -----------------------------------------------------------------------
# NAHRAVKA 1
nahravka1 = nahravka1[16000:32160]  # 1.01 sec
nahravka1_ramce = []
counter = 0
for i in range(100):
    sublist = []
    for j in range(320):
        helper = nahravka1[j + counter]
        helper -= np.mean(nahravka1)  # ustredneni
        helper /= np.abs(nahravka1).max()  # normalizace
        sublist.append(helper)
    nahravka1_ramce.append(sublist)
    counter += 160

# NAHRAVKA 2
nahravka2 = nahravka2[16000:32160]  # 1.01 sec
nahravka2_ramce = []
counter = 0
for i in range(100):
    sublist = []
    for j in range(320):
        helper = nahravka2[j + counter]
        helper -= np.mean(nahravka2)  # ustredneni
        helper /= np.abs(nahravka2).max()  # normalizace
        sublist.append(helper)
    nahravka2_ramce.append(sublist)
    counter += 160

ramce2vybrane = nahravka1_ramce[50] + nahravka2_ramce[50]
t = np.arange(len(ramce2vybrane)) / fs1

plt.plot(t, ramce2vybrane)
plt.figure(1)
plt.title('Ramec 1 - maskOFF | Ramec 2 - maskON')
plt.xlabel('time [s]')
plt.ylabel('y')
plt.show()

# -----------------------------------------------------------------------
# ------------ UKOL 4 ---------------------------------------------------
# -----------------------------------------------------------------------
def print_ramec(cislonahravky, cisloramce):
    if cislonahravky == "1":
        ramec_vybrany = nahravka1_ramce[cisloramce]
        t1 = (np.arange(len(ramec_vybrany)) / fs1)
    else:
        ramec_vybrany = nahravka2_ramce[cisloramce]
        t1 = (np.arange(len(ramec_vybrany)) / fs2)

    plt.plot(t1, ramec_vybrany)
    plt.title('Ramec')
    plt.xlabel('time [s]')
    plt.ylabel('y')
    plt.show()
    
# ------------ CENTER CLIPPING -----------------------------------------
def clipping(create_graph):
    ramec_clipping = []
    maximum_abs = np.abs(ramec_vybrany).max()
    for i in range (len(ramec_vybrany)):
        if ramec_vybrany[i] > (0.7*maximum_abs):
            ramec_clipping.append(int('1'))
        elif ramec_vybrany[i] < (-0.7*maximum_abs):
            ramec_clipping.append(int('-1'))
        else:
            ramec_clipping.append(int('0'))
            
    if create_graph == True:
        t2 = (np.arange(len(ramec_clipping)) / fs1)
        plt.plot(t2, ramec_clipping)
        plt.title('Centralni klipovani s 70%')
        plt.xlabel('time [s]')
        plt.ylabel('y')
        plt.show()
    return ramec_clipping

# ------------ AUTOKORELACE -----------------------------------------
def autocorrelation_math(ramec_clipping, k):
    ramec_clipping_my = ramec_clipping
    vysledok = 0
    for i in range(len(ramec_clipping_my) - int(k)):
        vysledok += (int(ramec_clipping_my[i]) * int(ramec_clipping_my[i+int(k)]))
    return vysledok

def autocorrelate(ramec_clipping, returnlag, create_graph):
    ramec_clipping_my2 = ramec_clipping
    lag_x = ['0']
    lag_y = ['0']
    prah_x = ['0']
    prah_y = ['0']
    ramec_correlate = []
    for i in range(len(ramec_clipping_my2)):
        ramec_correlate.append(autocorrelation_math(ramec_clipping_my2, i))
        if ((int(ramec_correlate[i]) > int(lag_y[0])) and i > 10):
            lag_y[0] = ramec_correlate[i]
            lag_x[0] = i / fs1
        elif i == 10:
            prah_x[0] = i / fs1
            prah_y[0] = ramec_correlate[0]

    if create_graph == True:  
        t3 = (np.arange(len(ramec_correlate)) / fs1)
        plt.plot(t3, ramec_correlate)
        plt.stem(lag_x, lag_y, linefmt='red', label="Lag")
        plt.stem(prah_x, prah_y, linefmt='b-', use_line_collection=True)
        plt.title('Autokorelace')
        plt.xlabel('time [s]')
        plt.ylabel('y')
        plt.legend()
        plt.show()
        
    if returnlag == True:
        return lag_x[0]*fs1
    else:
        return ramec_correlate

# ------------ ZAKLADNI FREKVENCE --------------------------------
zakladni_frekvence_nahravka1 = []
zakladni_frekvence_nahravka2 = []

for i in range(100):
    ramec_clipping = []
    ramec_vybrany = []
    ramec_vybrany = nahravka1_ramce[i]
    ramec_clipping = clipping(False)
    zakladni_frekvence_nahravka1.append(16000 / autocorrelate(ramec_clipping, True, False))
for i in range(100):
    ramec_clipping = []
    ramec_vybrany = []
    ramec_vybrany = nahravka2_ramce[i]
    ramec_clipping = clipping(False)
    zakladni_frekvence_nahravka2.append(16000 / autocorrelate(ramec_clipping, True, False))

#spustanie ulohy 4
print_ramec(1, 51)
ramec_vybrany = nahravka2_ramce[51]
ramec_clipping = clipping(True)
ramec_correlate = autocorrelate(ramec_clipping, False, True)

t4 = np.arange(len(zakladni_frekvence_nahravka1))
t5 = np.arange(len(zakladni_frekvence_nahravka2))
print("maskoff stred:", np.mean(zakladni_frekvence_nahravka1))
print("maskon stred:", np.mean(zakladni_frekvence_nahravka2))
print("maskoff rozptyl:", np.var(zakladni_frekvence_nahravka1))
print("maskon rozptyl:", np.var(zakladni_frekvence_nahravka2))
plt.plot(t4, zakladni_frekvence_nahravka1, color='red', label="bez rousky")
plt.plot(t5, zakladni_frekvence_nahravka2, color='blue', label="s rouskou")
plt.title('Zakladni frekvence ramcu')
plt.xlabel('ramce')
plt.ylabel('y')
plt.legend()
plt.show()        

# -----------------------------------------------------------------------
# ------------ UKOL 5 ---------------------------------------------------
# -----------------------------------------------------------------------
# ------------ VLASTNE DFT  --------------------------------
def vlastne_DFT(ramec_vybrany):
    dft_vysledok = []
    pi = cmath.pi
    for k in range(len(ramec_vybrany)):
        dft_helper = 0
        for n in range(len(ramec_vybrany)):
            exponent = cmath.exp(-2j * pi * (1 / len(ramec_vybrany)) * k * n)
            dft_helper += (ramec_vybrany[n] * exponent)
        dft_vysledok.append(dft_helper)
    return dft_vysledok

"""
#test vlastne DFT
ramec_vybrany = nahravka1_ramce[50]
vlastne = vlastne_DFT(ramec_vybrany)
original = np.fft.fft(ramec_vybrany)
print(vlastne[2])
print(original[2])
"""

# ------------ DFT nahravka 1  --------------------------------
dft_nahravka1 = [] 
for i in range(len(nahravka1_ramce)):
    dft_nahravka1.append(np.fft.fft(nahravka1_ramce[i], 1024))
       
log_ramce1 = []
for i in range(len(dft_nahravka1)):
    log_ramce1.append(10 * np.log10(np.abs(dft_nahravka1[i])**2))
  
log_ramce1 = np.transpose(log_ramce1)
log_ramce1 = log_ramce1[0:512]

# ------------ DFT nahravka 2  --------------------------------
dft_nahravka2 = []
for i in range(len(nahravka2_ramce)):
    dft_nahravka2.append(np.fft.fft(nahravka2_ramce[i], 1024))
       
log_ramce2 = []
for i in range(len(dft_nahravka2)):
    log_ramce2.append(10 * np.log10(np.abs(dft_nahravka2[i])**2))
  
log_ramce2 = np.transpose(log_ramce2)
log_ramce2 = log_ramce2[0:512]

# ------------ SPECTROGRAM nahravka1 PRINT--------------------
#RUN ULOHA 5
plt.imshow(log_ramce1, extent = [0 , 1.0, 0 , 8000], aspect="auto", origin="lower")
plt.title('Spektrogram bez rousky')
plt.xlabel('time [s]')
plt.ylabel('frekvencia')
cbar = plt.colorbar()
cbar.set_label('', rotation=270, labelpad=15)
plt.tight_layout()
plt.show()

# ------------ SPECTROGRAM nahravka2 PRINT--------------------
plt.imshow(log_ramce2, extent = (0 , 1.0, 0 , 8000), aspect="auto", origin="lower")
plt.title('Spektrogram s rouskou')
plt.xlabel('time [s]')
plt.ylabel('frekvencia')
cbar = plt.colorbar()
cbar.set_label('', rotation=270, labelpad=15)
plt.tight_layout()
plt.show()

# -----------------------------------------------------------------------
# ------------ UKOL 6 ---------------------------------------------------
# -----------------------------------------------------------------------

# ------------ FREKVENCNI CHARAKTERISTIKA -------------------------------
dft_nahravka1 = [] 
for i in range(len(nahravka1_ramce)):
    dft_nahravka1.append(np.fft.fft(nahravka1_ramce[i], n=1024))    
    
dft_nahravka2 = []
for i in range(len(nahravka2_ramce)):
    dft_nahravka2.append(np.fft.fft(nahravka2_ramce[i], n=1024))
       
freq_charakteristika = []
for i in range(100):
    freq_charakteristika_helper = []
    for j in range(1024):
        freq_charakteristika_helper.append(np.absolute(dft_nahravka2[i][j]) / np.absolute(dft_nahravka1[i][j]))
    freq_charakteristika.append(freq_charakteristika_helper)
    
freq_charakteristika = np.abs(freq_charakteristika)   
ramec_priemerne = []
for i in range(1024):
    helper = []
    for j in range(100):
        helper.append(freq_charakteristika[j][i])
    ramec_priemerne.append(np.mean(helper))
    
log_freq = []
for i in range(len(ramec_priemerne)):
    log_freq.append(10 * np.log10(np.abs(ramec_priemerne[i])**2))
    
# ------------ FREKVENCNI CHAR - PRINT --------------------
#RUN ULOHA 6
log_freq = log_freq[0:512]
t6 = (np.arange(len(log_freq)))
plt.plot(t6, log_freq)
plt.title('Frekvencni charakteristika rousky')
plt.xlabel('Vzorky')
plt.ylabel('Spektralna hustota')
plt.show()

# -----------------------------------------------------------------------
# ------------ UKOL 7 ---------------------------------------------------
# -----------------------------------------------------------------------

# ------------ FREKVENCNI CHARAKTERISTIKA -------------------------------
dft_nahravka1 = [] 
for i in range(len(nahravka1_ramce)):
    dft_nahravka1.append(np.fft.fft(nahravka1_ramce[i], n=1024))    
    
dft_nahravka2 = []
for i in range(len(nahravka2_ramce)):
    dft_nahravka2.append(np.fft.fft(nahravka2_ramce[i], n=1024))
       
freq_charakteristika = []
for i in range(100):
    freq_charakteristika_helper = []
    for j in range(1024):
        freq_charakteristika_helper.append(np.absolute(dft_nahravka2[i][j]) / np.absolute(dft_nahravka1[i][j]))
    freq_charakteristika.append(freq_charakteristika_helper)
    
freq_charakteristika = np.abs(freq_charakteristika)   
ramec_priemerne = []
for i in range(512):
    helper = []
    for j in range(100):
        helper.append(freq_charakteristika[j][i])
    ramec_priemerne.append(np.mean(helper))
    
idft = []
idft = np.fft.ifft(ramec_priemerne, n=1024)

# ------------ IDFT IMPLEMENTACE  -------------------------------
def vlastne_IDFT(ramec_vybrany):
    idft_vysledok = []
    pi = cmath.pi
    for k in range(len(ramec_vybrany)):
        idft_helper = 0
        for n in range(len(ramec_vybrany)):
            exponent = cmath.exp(2j * pi * (1 / len(ramec_vybrany)) * k * n)
            idft_helper += (ramec_vybrany[n] * exponent)
        idft_vysledok.append(idft_helper * (1 / len(ramec_vybrany)))
    return idft_vysledok

"""
#test vlastne IDFT
ramec_vybrany = nahravka1_ramce[50]
vlastne = vlastne_IDFT(ramec_vybrany)
original = np.fft.ifft(ramec_vybrany)
print(vlastne[2])
print(original[2])
"""

#RUN ULOHA 7
idft = idft[:512]
t6 = (np.arange(len(idft)))
plt.plot(t6, idft.real)
plt.title('Impulsni odezva rousky')
plt.xlabel('Vzorky')
plt.grid(alpha=0.5, linestyle='--')
plt.ylabel('y')
plt.show()

# -----------------------------------------------------------------------
# ------------ UKOL 8 ---------------------------------------------------
# -----------------------------------------------------------------------
fig, (ax1, ax2, ax3, ax4) = plt.subplots(4)

fs3, nahravka3 = wavfile.read('../audio/maskoff_sentence.wav')
nahravka3 = nahravka3[500:len(nahravka3)]
t8 = (np.arange(len(nahravka3)))
fs4, nahravka4 = wavfile.read('../audio/maskon_sentence.wav')
t9 = (np.arange(len(nahravka4)))
fs5, nahravka5 = wavfile.read('../audio/maskoff_tone.wav')
filter_apply_tone = lfilter(idft, [1], nahravka5)

filter_apply_sentence = lfilter(idft, [1], nahravka3)
t10 = (np.arange(len(filter_apply_sentence)))


ax1.plot(t8, nahravka3, color='orange', label="bez rousky")
ax1.plot(t10, filter_apply_sentence.real, color='green', label="simulace")
ax1.set_xlabel('Vzorky')
ax1.set_ylabel('y')
ax1.legend()

ax2.plot(t8, nahravka3, color='orange', label="bez rousky")
ax2.plot(t9, nahravka4, color='blue', label="s rouskou")
ax2.set_xlabel('Vzorky')
ax2.set_ylabel('y')
ax2.legend()

ax3.plot(t10, filter_apply_sentence.real, color='green', label="simulace")
ax3.plot(t9, nahravka4, color='blue', label="s rouskou")
ax3.set_xlabel('Vzorky')
ax3.set_ylabel('y')
ax3.legend()

ax4.plot(t8, nahravka3, color='orange', label="bez rousky")
ax4.plot(t9, nahravka4, color='blue', label="s rouskou")
ax4.plot(t10, filter_apply_sentence.real, color='green', label="simulace")
ax4.set_xlabel('Vzorky')
ax4.set_ylabel('y')
ax4.legend()

plt.subplots_adjust(hspace=0.5)
plt.show()

sf.write('../audio/sim_maskon_sentence.wav', np.abs(filter_apply_sentence).astype('int16'), 16000)
sf.write('../audio/sim_maskon_tone.wav', np.abs(filter_apply_tone).astype('int16'), 16000)

# -----------------------------------------------------------------------
# ------------ UKOL 13 --------------------------------------------------
# -----------------------------------------------------------------------

# ------------ FREKVENCNI CHARAKTERISTIKA -------------------------------
bez = log_freq
t13 = t6
zakladni_frekvence_rovnake = []
for i in range(len(zakladni_frekvence_nahravka1)):
    if (zakladni_frekvence_nahravka1[i] == zakladni_frekvence_nahravka2[i]):
        zakladni_frekvence_rovnake.append(i)
 
dft_nahravka1 = [] 
for i in range(len(zakladni_frekvence_rovnake)):
    dft_nahravka1.append(np.fft.fft(nahravka1_ramce[zakladni_frekvence_rovnake[i]], n=1024))
    
dft_nahravka2 = [] 
for i in range(len(zakladni_frekvence_rovnake)):
    dft_nahravka2.append(np.fft.fft(nahravka2_ramce[zakladni_frekvence_rovnake[i]], n=1024))  
    
       
freq_charakteristika = []
for i in range(len(zakladni_frekvence_rovnake)):
    freq_charakteristika_helper = []
    for j in range(1024):
        freq_charakteristika_helper.append(np.absolute(dft_nahravka2[i][j]) / np.absolute(dft_nahravka1[i][j]))
    freq_charakteristika.append(freq_charakteristika_helper)
  
freq_charakteristika = np.abs(freq_charakteristika)   
ramec_priemerne = []
for i in range(1024):
    helper = []
    for j in range(len(freq_charakteristika)):
        helper.append(freq_charakteristika[j][i])
    ramec_priemerne.append(np.mean(helper))
    
log_freq = []
for i in range(len(ramec_priemerne)):
    log_freq.append(10 * np.log10(np.abs(ramec_priemerne[i])**2))
    
# ------------ FREKVENCNI CHAR - PRINT --------------------
#RUN ULOHA 13
bez = bez[0:512]
log_freq = log_freq[0:512]
t14= (np.arange(len(log_freq)))

plt.plot(t14, log_freq, color='green', label="rovnaka frekvence")
plt.plot(t13, bez, color='red', label="vsechny ramce")
plt.title('Frekvencni charakteristika rousky')
plt.xlabel('Vzorky')
plt.ylabel('Spektralna hustota')
plt.legend()
plt.show()

idft = []
idft = np.fft.ifft(ramec_priemerne, n=1024)
idft = idft[:512]

fs3, nahravka3 = wavfile.read('../audio/maskoff_sentence.wav')
nahravka3 = nahravka3[500:len(nahravka3)]
fs5, nahravka5 = wavfile.read('../audio/maskoff_tone.wav')
filter_apply_tone = lfilter(idft, [1], nahravka5)
filter_apply_sentence = lfilter(idft, [1], nahravka3)

sf.write('../audio/sim_maskon_sentence_only_match.wav', np.abs(filter_apply_sentence).astype('int16'), 16000)
sf.write('../audio/sim_maskon_tone_only_match.wav', np.abs(filter_apply_tone).astype('int16'), 16000)

