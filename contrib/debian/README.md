
Debian
====================
This directory contains files used to package zuzcoind/zuzcoin-qt
for Debian-based Linux systems. If you compile zuzcoind/zuzcoin-qt yourself, there are some useful files here.

## zuzcoin: URI support ##


zuzcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install zuzcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your zuzcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/zuzcoin128.png` to `/usr/share/pixmaps`

zuzcoin-qt.protocol (KDE)

