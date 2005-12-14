; meanwhile.nsi
;
; A simple script for installing meanwhile-gaim
;
; Stephen Dawkins <elfarto at elfarto dot com>
;--------------------------------

; The name of the installer
Name "Meanwhile Gaim"

; The file to write
OutFile "${PREFIX}/dist/meanwhile-gaim-${VERSION}.exe"

; The default installation directory
InstallDir $PROGRAMFILES\Gaim

; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically)
InstallDirRegKey HKLM "Software\Gaim" "Install_Dir"

;--------------------------------

Page directory
Page instfiles

Section ""
  SetOutPath $INSTDIR

  Delete libmeanwhile-0.dll
  Delete libmeanwhile-1.dll
  Delete libmeanwhile.dll
  Delete plugins\libmwgaim.dll
  Delete plugins\meanwhile-gaim.dll
 
  File /oname=pixmaps\gaim\status\default\meanwhile.png ${PREFIX}/share/pixmaps/gaim/status/default/meanwhile.png
  File /oname=pixmaps\gaim\status\default\external.png ${PREFIX}/share/pixmaps/gaim/status/default/external.png
  File /oname=plugins\libmwgaim.dll ${PREFIX}/lib/gaim/libmwgaim.dll
  File ${PREFIX}/bin/libmeanwhile-1.dll
SectionEnd ; end the section
