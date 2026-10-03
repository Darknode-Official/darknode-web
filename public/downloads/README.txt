Put the built desktop-app installers here so the website can serve them directly.
The landing page's download buttons link to these exact filenames:

  Darknode-linux.deb        (Linux)   built with:  npm run dist:linux   (in darknode-app)
  Darknode-linux.AppImage   (Linux)   built with:  npm run dist:linux   (portable, non-Debian distros)
  Darknode-windows.exe      (Windows) built with:  npm run dist:win     (on Windows or via Wine)

How to fill this folder:
  1. In ~/projects/darknode-app, build the installer:
       npm run dist:linux    -> dist/darknode-app_1.0.0_amd64.deb   (also builds an AppImage)
       npm run dist:win       -> dist/Darknode Setup 1.0.0.exe
  2. Copy + rename into this folder:
       cp dist/darknode-app_1.0.0_amd64.deb  Darknode-linux.deb
       cp "dist/Darknode Setup 1.0.0.exe"    Darknode-windows.exe
  3. Deploy:  cd ~/projects/darknode-web && firebase deploy --only hosting

What users run after downloading:
  Linux    sudo apt install ./Darknode-linux.deb      (then launch "Darknode" from the app menu, or run: darknode)
  Windows  double-click Darknode-windows.exe          (SmartScreen: More info -> Run anyway; installer is unsigned)

Notes:
  - The .deb is preferred over the AppImage on Linux: no FUSE dependency, it sets up the
    Chromium sandbox correctly, and it adds Darknode to the application menu automatically.
  - Installers are ~90-100 MB each.
  - Installers are git-ignored; deploy with: firebase deploy --only hosting
