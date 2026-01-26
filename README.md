## Vanquish's Media Vault


Vanquish Vault is a personal file encryption locker built with Python and PyQt6. It utilizes AES-256 GCM encryption to secure private files, images, and videos. The application features a custom user interface.   
  
# TECHNICAL SPECIFICATIONS  
This application manages data through an encrypted directory structure:  

ENCRYPTION: The application generates a unique random ID for every imported file and encrypts the raw binary data using a master key derived from your access code.  

OBFUSCATION: Original filenames and extensions are stripped and replaced with hex-encoded strings (e.g., a1b2c3d4.enc) to prevent metadata leaks at the OS level.  

SECURE METADATA: File hierarchies and original names are stored in an encrypted database that is only decrypted into memory after successful authentication.  

MEDIA HANDLING: The application includes a custom preview engine that generates temporary thumbnails for images and videos using memory-buffered streams.  
  
# IMPORTANT NOTES:  

USAGE WARNING: Do not use this as the sole backup for critical or high-stakes data.  
DATA RECOVERY: There is no administrative override or password recovery mechanism. If the access code is forgotten, the master key cannot be recovered, and all data within the vault will be permanently inaccessible.  
  
# CORE FEATURES   
  
BRUTE FORCE PREVENTION: Automated lockout timers triggered by consecutive failed login attempts.  
   
# compiling:  
pyinstaller --noconfirm --onefile --windowed --name "VanquishVault" --icon "icon.ico" --collect-all "cryptography" vanquish_ultimate.py  
   
# DEPENDENCIES  
Python 3.10 or higher  

PyQt6 (Interface)  

Cryptography (Security Engine)  

Pillow (Image Processing)  

OpenCV (Video Processing)  

  
# TECHNICAL SPECIFICATIONS  
This application manages data through an encrypted directory structure:  

ENCRYPTION: The application generates a unique random ID for every imported file and encrypts the raw binary data using a master key derived from your access code.  

OBFUSCATION: Original filenames and extensions are stripped and replaced with hex-encoded strings (e.g., a1b2c3d4.enc) to prevent metadata leaks at the OS level.  

SECURE METADATA: File hierarchies and original names are stored in an encrypted database that is only decrypted into memory after successful authentication.  

MEDIA HANDLING: The application will include a custom preview engine that generates temporary thumbnails for images and videos using memory-buffered streams in future.  
