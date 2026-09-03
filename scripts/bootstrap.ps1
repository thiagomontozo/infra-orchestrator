param([string]$Origin='http://localhost:8080')
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath '.env') { throw '.env already exists; preserve its encryption key.' }
$configText=Get-Content -Raw -LiteralPath '.env.example'
$dbPassword=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)).ToLower()
$encryptionKey=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$configText=$configText.Replace('POSTGRES_PASSWORD=',"POSTGRES_PASSWORD=$dbPassword").Replace('ENCRYPTION_KEY=',"ENCRYPTION_KEY=$encryptionKey").Replace('PUBLIC_ORIGIN=https://infra.example.com',"PUBLIC_ORIGIN=$Origin")
if ($Origin.StartsWith('http://localhost:') -or $Origin.StartsWith('http://127.0.0.1:')) {$configText=$configText.Replace('APP_ENV=production','APP_ENV=development')}
[IO.File]::WriteAllText((Join-Path (Get-Location) '.env'),$configText)
Write-Output 'Created .env with random secrets. Configure allowed outbound CIDRs, then run docker compose up --build -d.'
