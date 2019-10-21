rem Removing all content in /bin and /obj /out - this is a robust clean!  You will need to run CMake again.
rem This is needed because Visual Studio doesn't support cleaning CMake projects quite yet.  It's coming though.

for /d /r . %%d in (bin,obj,out) do @if exist "%%d" rd /s/q "%%d"