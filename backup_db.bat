@echo off
set DB_FILE=src\stellar_wallet.db
set BACKUP_DIR=backups
set TIMESTAMP=%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set BACKUP_FILE=%BACKUP_DIR%\stellar_wallet_%TIMESTAMP%.db

if not exist %BACKUP_DIR% (
    mkdir %BACKUP_DIR%
)

copy %DB_FILE% %BACKUP_FILE%
echo Backup created: %BACKUP_FILE%
pause 