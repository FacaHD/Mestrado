import pyotp
import qrcode
#Generate QR Code

url = pyotp.totp.TOTP('JBSWY3DPEHPK3PXP').provisioning_uri(name='sousadaniel948@gmail.com', issuer_name='Secure App')
ptotp = pyotp.TOTP("JBSWY3DPEHPK3PXP")

(print("Current OTP:", ptotp.now()))
img = qrcode.make(url)
img.save('ola.png')