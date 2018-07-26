# php_powermemory
An extension for PHP language (7.0 or higher) for reading/writing process memory and memory pattern-scanning

Latest version: 1.2.2

## How to compile
For now it's Windows-only project. Recommended to compile it only with Microsoft Visual Studio 2017.


1. Download and install PHP version 7.0 or higher and download sources of this same version of PHP you downloaded.
2. Extract PHP sources to some directory, for example: `D:/php/src`
3. Clone this project to your local storage
4. Open it in Visual Studio
5. Open project settings and add to include directories following directories: `D:\php\src`, `D:\php\src\main`, `D:\php\src\TSRM` and `D:\php\src\Zend`
6. Add to references and library directories this directory: `D:\php\dev`
7. In linker settings add to input lib files this library `php7ts.lib`
8. Add to linker command line this: `/FORCE:MULTIPLE `
9. In general project settings, set output path to: `D:\php\ext\'
10. Try to compile it (Don't forget to change configuration to Release)

## How to use it
Open php.ini and change following lines:
1. Change max exec time to 0 and max input time to -1: `max_execution_time = 0`, `max_input_time = -1`
2. After all extension includes add this line: `extension = php_PowerMemory.dll`
3. Now it should be ready for using. Run `echo PowerMem_Help();` on PHP to check if it works.




