<?php
namespace FreePBX\modules\Certman;
use FreePBX\modules\Backup as Base;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
class Backup Extends Base\BackupBase{
  public $dirs = [];
  public function runBackup($id,$transaction){
    $this->certman2 = $this->FreePBX->Certman;
    $this->buildFileStructure()
      ->addDirectories($this->dirs);
    $this->addDependency('core');
    $this->addConfigs($this->buildConfigs());
  }

  public function buildConfigs(){
    return [
      'managedCerts' => $this->certman2->getAllManagedCertificates(),
      'managedCSRs' => $this->certman2->getAllManagedCSRs(),
      'dtlsOptions' => $this->certman2->getAllDTLSOptions(),
      'keyDir' => $this->certman2->PKCS->getKeysLocation()
    ];
  }
  
  public function buildFileStructure(){
    $keyDir = $this->certman2->PKCS->getKeysLocation();
    $this->dirs[] = $keyDir;
    $directory = new RecursiveDirectoryIterator($keyDir);
    $iterator = new RecursiveIteratorIterator($directory);
    foreach ($iterator as $fileObj) {
      if($fileObj->isDir()){
        $this->dirs[] = $fileObj->getPath();
        continue;
      }
      $this->addFile($fileObj->getBasename(), $fileObj->getPath(), '', $fileObj->getExtension());
    }
    $this->dirs = array_unique($this->dirs);
    return $this;
  }
}
