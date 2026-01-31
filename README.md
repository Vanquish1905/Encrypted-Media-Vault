## Vanquish's Media Vault


Vanquish Vault is a personal file encryption locker built with Python and PyQt6. It utilizes AES-256 GCM encryption to secure private files, images, and videos. The application features a custom user interface.   
  
# TECHNICAL SPECIFICATIONS  
This application manages data through an encrypted directory structure:  

ENCRYPTION: The application generates a unique random ID for every imported file and encrypts the raw binary data using a master key derived from your access code.  

OBFUSCATION: Original filenames and extensions are stripped and replaced with hex-encoded strings (e.g., a1b2c3d4.enc) to prevent metadata leaks at the OS level.  

SECURE METADATA: File hierarchies and original names are stored in an encrypted database that is only decrypted into memory after successful authentication.  

MEDIA HANDLING: The application includes a custom preview engine that generates temporary thumbnails for images and videos using memory-buffered streams.  
  


# ⚠️ Important: Usage Instructions  
You must close the application when you are finished using it. When you open a file for viewing (like an image or document), the vault decrypts it into a temporary "cache" directory within the application's data folder. This cache is only cleared and deleted when the application is properly closed. Leaving the application open or terminating it forcefully may leave decrypted files in your temporary folder.   
  
# CORE FEATURES   
  
BRUTE FORCE PREVENTION: Automated lockout timers triggered by consecutive failed login attempts.  
   
# compiling:  
pyinstaller --noconsole --onefile --icon=icon.ico --collect-all customtkinter --add-data "icon.ico;." vanquish_vault.py
   
# DEPENDENCIES  
Python 3.10 or higher  

customtkinter  

argon2-cffi (Password hashing)

PyQt6 (Interface)  

Cryptography (Security Engine)  

Pillow (Image Processing)  

OpenCV (Video Processing)    

customtkinter  
  
Already Build in Libaries:  

secrets  

hashlib  

base64  

os  

sys  

json  

shutil  

threading  

datetime  

time  

tempfile  

io  

tkinter  
  
# TECHNICAL SPECIFICATIONS  
This application manages data through an encrypted directory structure:  

ENCRYPTION: The application generates a unique random ID for every imported file and encrypts the raw binary data using a master key derived from your access code.  

OBFUSCATION: Original filenames and extensions are stripped and replaced with hex-encoded strings (e.g., a1b2c3d4.enc) to prevent metadata leaks at the OS level.  

SECURE METADATA: File hierarchies and original names are stored in an encrypted database that is only decrypted into memory after successful authentication.  

MEDIA HANDLING: The application will include a custom preview engine that generates temporary thumbnails for images and videos using memory-buffered streams in future.  
