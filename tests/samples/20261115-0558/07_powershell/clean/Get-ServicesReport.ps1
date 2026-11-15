Get-Service | Where-Object Status -eq 'Running' | Sort-Object DisplayName | Select-Object -First 20
