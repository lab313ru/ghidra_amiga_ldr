# Ghidra - Amiga Executable Hunks loader

- [install](#install)
- [build](#build)
- [debug](#debug)


## install

- download the ZIP archive for your Ghidra version from the 
  [extension Releases page][extension-download] and save it the 
  `<GhidraInstallDir>`**/Extensions/Ghidra/** directory
- start Ghidra (`<GhidraInstallDir>`**/ghidraRun**) and 
  select `File -> Install Extensions...` in the menu

For more details read the _Installing Ghidra_ and _Ghidra Extension Notes_ 
sections in the [Ghidra Installation Guide][ghidra-install-guide].

[extension-download]: https://github.com/lab313ru/ghidra_amiga_ldr/releases
[ghidra-install-guide]: https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/InstallationGuide.html


## build

Make sure you have the [build dependencies][ghidra-build-depends] installed 
(Java JDK 11, gradle 6.8+, git) and that gradle uses the right Java version 
(check `gradle -v` and set `JAVA_HOME` for selecting another Java version).

- download and unzip the [Ghidra release][ghidra-download] for which you want 
  to build the extension
- open a shell and checkout the extension source tree:  
  ```bash
  mkdir ~/git
  cd ~/git

  git clone git@github.com:lab313ru/ghidra_amiga_ldr.git
  cd ghidra_amiga_ldr
  ```
- build the extension with gradle, where `<GhidraInstallDir>` is the absolute 
  path to your Ghidra target release installation:  
  ```bash
  gradle -PGHIDRA_INSTALL_DIR="<GhidraInstallDir>"
  ```
- on success your extension ZIP archive can be found in 
  _ghidra_amiga_ldr_**/dist**

[ghidra-build-depends]: https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md#catalog-of-dependencies
[ghidra-download]: https://github.com/NationalSecurityAgency/ghidra/releases


## debug

Read the Ghidra [Developer's Guide][ghidra-dev-guide] first.

The easiest way is to checkout the extension source tree
into an already prepared Ghidra source tree:  
```bash
mkdir ~/git
cd ~/git

# use '--branch=stable' if the default branch is currently broken
git clone git@github.com:NationalSecurityAgency/ghidra.git ghidra-amiga
cd ghidra-amiga
gradle -I gradle/support/fetchDependencies.gradle init
gradle prepDev eclipse buildNatives
git clone git@github.com:lab313ru/ghidra_amiga_ldr.git Ghidra/Extensions/ghidra_amiga_ldr
```

Download the [Eclipse IDE][eclipse-download] installer and 
install the `Eclipse IDE for Java Developers`.

Open a new  Eclipse workspace (e.g. `~/git/ghidra-amiga-workspace`), 
select `File -> Import`, expand `General`, 
select `Existing Projects into Workspace`, click `Ǹext >`, 
`Select the root directory:` browse to the Ghidra source tree, 
select `Search for nested projects`, click `Select All`, 
and click `Finish`.

Wait for the build to complete in the background, and 
select `Run -> Debug Configurations...` in the menu, 
expand `Java Application`, select `Ghidra`, and click `Debug`.

If you do not want to repeat the last step over and over:
Select `Window -> Preferences`, expand `Run/Debug`, select `Launching`, 
select `Always launch the previously launched application`, 
click `Apply and Close`.

[ghidra-dev-guide]: https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md
[eclipse-download]: https://www.eclipse.org/downloads/

