#!/bin/bash
# -----------------------------------------------------------
# ctf vm setup script installs a set of pentesting and
# reversing tools for more shells and more flags. intended
# for apt-based systems, tested on ubuntu 16.04.
# 
# personalized with contributions from: 
#
#   g0tmi1k: https://github.com/g0tmi1k/os-scripts
#   epic treasure: https://github.com/ctfhacker/EpicTreasure
#   pentest framework: https://github.com/trustedsec/ptf
# -----------------------------------------------------------


# -----------------------------------------------------------
# script usage
# -----------------------------------------------------------
function usage() {
  echo "[*] CTF VM Setup"
  echo "[*] Run this as a regular user"
  echo "[*] Usage: ${0} <e|i|p>"
  echo
  echo "      e - Epic Treasure"
  echo "      i - Initial Setup (RUN ME FIRST)"
  echo "      p - Pentest Framework"
  echo
  exit 1
}


# -----------------------------------------------------------
# put basics into place
# -----------------------------------------------------------
function init_setup() {
  # -----------------------------------------------------------
  # get sudo in gear
  # -----------------------------------------------------------
  echo "[*] Firing up sudo"
  run=$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | md5sum - | awk '{print $1}')
  sudo touch "$HOME/.$run"

  # -----------------------------------------------------------
  # sudo for life
  # -----------------------------------------------------------
  echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers.d/99-$USER

  # -----------------------------------------------------------
  # upgrade all the things
  # -----------------------------------------------------------
  sudo apt update
  sudo apt -y dist-upgrade

  # -----------------------------------------------------------
  # get necessities
  # -----------------------------------------------------------
  sudo apt -y install build-essential git grc open-vm-tools-desktop terminator vim
  wget -O $HOME/.git-prompt.sh "https://raw.githubusercontent.com/git/git/master/contrib/completion/git-prompt.sh"

  # -----------------------------------------------------------
  # try to install chrome
  # -----------------------------------------------------------
  mkdir -p $HOME/tools/chrome
  cd $HOME/tools/chrome
  wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
  dependencies=$(dpkg -I google-chrome-stable_current_amd64.deb | grep --color=never "^ Depends" | sed -e "s/ Depends://g" | tr ',' '\n' | sed -e "s/ (>.\+)//g" | tr -d '\n')
  sudo apt -y install $dependencies
  sudo dpkg -i google-chrome-stable_current_amd64.deb
  cd -

  # -----------------------------------------------------------
  # biohazard wallpaper
  # -----------------------------------------------------------
  wget -O "$HOME/Pictures/biohazard_1680x1050.jpg" "https://i.imgur.com/DDHrJ2C.jpg"

  # -----------------------------------------------------------
  # configs, now from github
  # -----------------------------------------------------------
  mkdir -p $HOME/.config/terminator
  wget -O $HOME/.config/terminator/config "https://raw.githubusercontent.com/int0x80/dotfiles/master/terminator/config"
  wget -O $HOME/.bashrc "https://raw.githubusercontent.com/int0x80/dotfiles/master/bashrc"
  wget -O $HOME/.bash_aliases "https://raw.githubusercontent.com/int0x80/dotfiles/master/bash_aliases"
  wget -O $HOME/.vimrc "https://raw.githubusercontent.com/int0x80/dotfiles/master/vimrc"

  # -----------------------------------------------------------
  # cleaning up
  # -----------------------------------------------------------
  sudo rm "$HOME/.$run"

  # -----------------------------------------------------------
  # browser extensions
  # -----------------------------------------------------------
  echo "[*] Some browser extensions to add:"
  echo " +  uBlock Origin"
  echo " +  HTTPS Everywhere"
  echo " +  Flashblock (Firefox)"
  echo " +  Proxy Changing: FoxyProxy (Firefox) / Proxy SwitchyOmega (Chrome)"
}



# -----------------------------------------------------------
# pentest framework components
# -----------------------------------------------------------
function ptf_setup() {
  mkdir -p $HOME/tools
  cd $HOME/tools
  git clone https://github.com/trustedsec/ptf
  sudo $HOME/tools/ptf/ptf use modules/install_update_all
}


# -----------------------------------------------------------
# epic treasure components
# -----------------------------------------------------------
function epic_treasure() {
  sudo apt -y install python3-pip gdb gdb-multiarch unzip foremost ipython silversearcher-ag

  # Install pwntools 3.x
  sudo apt -y install python2.7 python-pip python-dev git libssl-dev
  sudo pip install --upgrade pwntools
  echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

  cd $HOME
  mkdir tools
  cd tools

  # Install pwndbg
  git clone https://github.com/zachriggle/pwndbg
  echo source `pwd`/pwndbg/gdbinit.py >> ~/.gdbinit

  # Capstone for pwndbg
  git clone https://github.com/aquynh/capstone
  cd capstone
  git checkout -t origin/next
  sudo ./make.sh install
  cd bindings/python
  sudo python3 setup.py install # Ubuntu 14.04+, GDB uses Python3

  # Unicorn for pwndbg
  cd $HOME/tools
  sudo apt install libglib2.0-dev
  git clone https://github.com/unicorn-engine/unicorn
  cd unicorn
  sudo ./make.sh install
  cd bindings/python
  sudo python3 setup.py install # Ubuntu 14.04+, GDB uses Python3

  # pycparser for pwndbg
  sudo pip3 install pycparser # Use pip3 for Python3

  # Install radare2
  cd $HOME/tools
  git clone https://github.com/radare/radare2
  cd radare2
  ./sys/install.sh

  # Install binwalk
  cd $HOME/tools
  git clone https://github.com/devttys0/binwalk
  cd binwalk
  sudo python setup.py install
  sudo apt install squashfs-tools

  # Install Firmware-Mod-Kit
  sudo apt -y install git build-essential zlib1g-dev liblzma-dev python-magic
  cd $HOME/tools
  wget https://firmware-mod-kit.googlecode.com/files/fmk_099.tar.gz
  tar xvf fmk_099.tar.gz
  rm fmk_099.tar.gz
  cd fmk_099/src
  ./configure
  make

  # Uninstall capstone
  sudo pip2 uninstall capstone -y

  # Install correct capstone
  cd $HOME/tools/capstone/bindings/python
  sudo python setup.py install

  # Install Angr
  cd $HOME
  sudo apt -y install python-dev libffi-dev build-essential virtualenvwrapper
  sudo pip install angr --upgrade

  # Install american-fuzzy-lop
  cd $HOME/tools
  sudo apt -y install clang llvm
  wget --quiet http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
  tar -xzvf afl-latest.tgz
  rm afl-latest.tgz
  wget --quiet http://llvm.org/releases/3.8.0/clang+llvm-3.8.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz
  xz -d clang*
  tar xvf clang*
  cd clang*
  cd bin
  export PATH=$PWD:$PATH
  cd ../..
  (
    cd afl-*
    make
    # build clang-fast
    (
      cd llvm_mode
      make
    )
    sudo make install

    # build qemu-support
    sudo apt -y install libtool automake bison libglib2.0-dev
    ./build_qemu_support.sh
  )

  # Install 32 bit libs
  sudo dpkg --add-architecture i386
  sudo apt update
  sudo apt -y install libc6:i386 libncurses5:i386 libstdc++6:i386
  sudo apt -y install libc6-dev-i386

  # Install apktool - from https://github.com/zardus/ctf-tools
  cd $HOME/tools
  apt update
  apt install -y default-jre
  wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
  wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.1.1.jar
  sudo mv apktool_2.1.1.jar /bin/apktool.jar
  sudo mv apktool /bin/
  sudo chmod 755 /bin/apktool
  sudo chmod 755 /bin/apktool.jar

  # Install Pillow
  sudo apt build-dep python-imaging
  sudo apt -y install libjpeg8 libjpeg62-dev libfreetype6 libfreetype6-dev
  sudo pip install Pillow

  # Install r2pipe
  sudo pip install r2pipe

  # Install ROPGadget
  cd $HOME/tools
  git clone https://github.com/JonathanSalwan/ROPgadget
  cd ROPgadget
  sudo python setup.py install

  # Install libheap in GDB
  cd $HOME/tools
  git clone https://github.com/cloudburst/libheap
  cd libheap
  sudo cp libheap.py /usr/lib/python3.5
  echo "python from libheap import *" >> ~/.gdbinit
}


# -----------------------------------------------------------
# main
# -----------------------------------------------------------
command=${1:0:1}
case $command in
  "e")
    epic_treasure
    ;;

  "i")
    init_setup
    ;;

  "p")
    ptf_setup
    ;;

  *)
    usage
    ;;
esac
