# PE_import-_adder
Add a new section in the PE file, and copy old import descriptor to the new section then insert a new dll file into the import directory.

how to user?
In cmd windows, you should input like this:ImportAdder.exe F:\dmp\PE\PE.exe Zone1.dll Zone1

For x64bit PE，you should build with x64bit， for 32bit PE ,you should build with 32bit in vritualstudio 2019