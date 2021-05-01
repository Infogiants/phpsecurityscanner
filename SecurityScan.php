<?php
/**
 * PHP Scanner for Vulnerable functions
 * @version 1.0
 */

/**
 * PHP Security Scanner
 */
class SecurityScan
{   
    /**
     * File format to be scanned
     */
    const SCANFILEFORMAT = 'php';
    const ERRORLINELIMITSTART = 0;
    const ERRORLINELIMITEND = 45;
    
    /**
     * Scan Directory
     */
    private $scanDir;
    
    /**
     * Vulnerable Database
     */
    private $vulnerableDatabase;
    
    /**
     * Error Count
     */
    private $errorCount;
    
    /**
     * Constructor
     */
    public function __construct($dir)
    {   
        $this->errorCount = 0;
        $this->scanDir = $dir;
        $this->vulnerableDatabase = [
            ' system(',
            ' exec(',
            ' popen(',
            ' pcntl_exec(',
            ' eval(',
            ' create_function('
        ];
        $this->scanDirectoryFiles();
    }
    
    /**
     * Recursive Find Files
     * @return []
     */
    public static function findRecursiveFilesByFormat($path, $format) {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path),
                RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $path) {
            if ($path->isDir()) {
                //skip directories
                continue;
            } else {
                $fileNameArr = explode(".", $path);
                if ($format === end($fileNameArr)) {
                    $files[] = $path->__toString();
                }
            }
        }
        return $files;
    }
    
    /**
     * Scan Code Directory
     * @return void
     */
    public function scanDirectoryFiles() {
        if(!file_exists($this->scanDir)){
            echo PHP_EOL."\e[0;30;41m Incorrect Directory Path \e[0m".PHP_EOL.PHP_EOL;
            return false;
        }
        foreach (new DirectoryIterator($this->scanDir) as $dir) {
            if ($dir->isDir() && !$dir->isDot()) {
                $this->modulesDirectories[] = $dir->getFilename();
            }
        }
        if (count($this->modulesDirectories) > 0) {
            foreach ($this->modulesDirectories as $subDir) {
                $this->tmpDirs[$subDir] = self::findRecursiveFilesByFormat($this->scanDir . "/" . $subDir, self::SCANFILEFORMAT);
            }
            
            $this->tmpDirs[count($this->modulesDirectories) + 1] = self::findRecursiveFilesByFormat($this->scanDir, self::SCANFILEFORMAT);
            
            //Loop and Read Files and check for vulenrable database patterns
            foreach ($this->tmpDirs as $files) {
                if(!empty($files)) {
                    foreach ($files as $file) {
                        $badLines = null;
                        $lines = file($file, FILE_IGNORE_NEW_LINES); // Read the file into an array
                        $lineIndex = 0;
                        foreach ($lines as $key => $line) {
                            //Scan Line aganinst vulenrable databse
                            foreach ($this->vulnerableDatabase as $defination) {
                                if (stristr($line, $defination)) {
                                    $this->errorCount++;
                                    //Increment error count flag
                                    $badLines .= PHP_EOL."\e[1;33;41m Record :\e[0m\e[0;30;46m ".$this->errorCount." \e[0m".PHP_EOL.PHP_EOL;
                                    $badLines .= "\e[0;30;42m File Path \e[0m: ".$file.PHP_EOL.PHP_EOL;
                                    $badLines .= "\e[0;30;42m Line Number \e[0m: ".$key.PHP_EOL.PHP_EOL;
                                    $badLines .= "\e[0;30;42m Line Content \e[0m:". $line.PHP_EOL.PHP_EOL;
                                    $badLines .= "\e[0;30;42m Error \e[0m:". trim(htmlspecialchars(substr(stristr($line, $defination), self::ERRORLINELIMITSTART, self::ERRORLINELIMITEND))) . PHP_EOL;
                                }
                            }
                            $lineIndex++;
                        }
                        echo $badLines;
                    }
                }
            }
            echo PHP_EOL."\e[1;33;41mTotal Vulenrabilities Found:\e[0m". "\e[0;30;46m ".$this->errorCount." \e[0m".PHP_EOL.PHP_EOL;
        }
    }
}

//Intialize with folder path to scan
if(empty($argv[1])){
    echo PHP_EOL."\e[0;30;41m Please provide directory path to scan \e[0m".PHP_EOL.PHP_EOL;
    return false;
}

$obj = new SecurityScan($argv[1]);