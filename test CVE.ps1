# Проверка уязвимости CVE-2023-##### и обновления KB5032189
function Check-YazvAndUpdate {
    $yazvKB = "CVE-2023-#####"
    $updateKB = "KB5032189"
    $updateURL = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2023/11/windows10.0-kb5032189-x64_0a3b690ba3fa6cd69a2b0f989f273cfeadba745f.msu"

    # Проверка наличия обновления KB5032189
    $updateInstalled = Get-HotFix | Where-Object {$_.HotFixID -eq $updateKB}

    if ($updateInstalled) {
        Write-Host "Обновление $updateKB уже установлено."
    } else {
        Write-Host "Компьютер подвержен уязвимости $yazvKB."
        Write-Host "Необходимо установить обновление $updateKB."

        # Предложение скачать и установить обновление
        $installChoice = Read-Host "Хотите скачать и установить обновление? (Y/N)"

        if ($installChoice -eq 'Y' -or $installChoice -eq 'y') {
            Write-Host "Скачивание обновления $updateKB..."
            $updatePath = "C:\Temp\$updateKB.msu"  # Путь для сохранения файла

            # Загрузка обновления
            Invoke-WebRequest -Uri $updateURL -OutFile $updatePath

            # Установка обновления
            Write-Host "Установка обновления $updateKB..."
            Start-Process -FilePath "wusa.exe" -ArgumentList $updatePath -Wait
        } else {
            Write-Host "Обновление не установлено. Компьютер остается уязвимым."
        }
    }
}
# Вызов функции для проверки уязвимости и установки обновления
Check-YazvAndUpdate
