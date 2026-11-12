@echo off
setlocal enabledelayedexpansion

:: Dossier racine contenant les fichiers source
set "source_dir=.\"
:: Fichier de sortie
set "output_file=all.txt"

:: Supprimer le fichier de sortie s'il existe
if exist "%output_file%" del "%output_file%"

:: Parcourir récursivement tous les fichiers .java
for /r "%source_dir%" %%f in (*.java) do (
    :: Récupérer le chemin relatif par rapport à source_dir
    set "relative_path=%%~pf"
    set "relative_path=!relative_path:%source_dir%\=!"
    set "relative_path=!relative_path:\=/!"  :: Remplacer les \ par / pour éviter les problèmes

    :: Écrire le chemin relatif + nom du fichier comme séparateur
    echo ///FILE_SEPARATOR///!relative_path!%%~nxf >> "%output_file%"

    :: Ajouter le contenu du fichier
    type "%%f" >> "%output_file%"
)

echo Assemblage terminé : %output_file%
pause
