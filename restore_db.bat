@echo off
set DB_FILE=src\stellar_wallet.db
set BACKUP_DIR=backups

echo Available backups:
dir /b %BACKUP_DIR%\stellar_wallet_*.db

set /p BACKUP_FILE="Enter the backup filename to restore: "

if exist %BACKUP_DIR%\%BACKUP_FILE% (
    copy /Y %BACKUP_DIR%\%BACKUP_FILE% %DB_FILE%
    echo Database restored from %BACKUP_FILE%
) else (
    echo Backup file not found!
)
pause 