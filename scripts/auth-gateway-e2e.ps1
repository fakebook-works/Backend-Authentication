param(
    [string]$GatewayUrl = 'http://localhost:2001/graphql',
    [string]$AuthenticationUrl = 'http://localhost:1001/graphql',
  [string]$PostgresContainer = 'fakebook-auth-e2e-db',
  [string]$Database = 'fakebook',
  [string]$GatewaySecret = 'local-gateway-secret-at-least-32-bytes-2026',
  [string]$PaymentSecret = 'local-payment-secret-at-least-32-bytes-2026'
)

$ErrorActionPreference = 'Stop'
$gateway = $GatewayUrl
$auth = $AuthenticationUrl
$gatewayOrigin = ([Uri]$gateway).GetLeftPart([UriPartial]::Authority)
$authOrigin = ([Uri]$auth).GetLeftPart([UriPartial]::Authority)
$repoRoot = Split-Path $PSScriptRoot -Parent
$suffix = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$maleEmail = "authmale$suffix@example.com"
$femaleEmail = "authfemale$suffix@example.com"
$password = 'Password123!'
$changedPassword = 'ChangedPassword123!'
$resetPassword = 'ResetPassword123!'
$assertions = [System.Collections.Generic.List[string]]::new()

function Assert-True([bool]$condition, [string]$name) {
  if (-not $condition) { throw "Assertion failed: $name" }
  $assertions.Add($name)
}

function Invoke-GraphQl {
  param([string]$Url, [string]$Query, [hashtable]$Variables = @{}, [Microsoft.PowerShell.Commands.WebRequestSession]$Session, [string]$Token, [hashtable]$ExtraHeaders = @{})
  $headers = @{} + $ExtraHeaders
  if ($Token) { $headers.Authorization = "Bearer $Token" }
  $params = @{ Uri = $Url; Method = 'Post'; ContentType = 'application/json'; Body = (@{ query = $Query; variables = $Variables } | ConvertTo-Json -Depth 20 -Compress); Headers = $headers; SkipHttpErrorCheck = $true }
  if ($Session) { $params.WebSession = $Session }
  $response = Invoke-WebRequest @params
  $content = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
  $json = $content | ConvertFrom-Json -Depth 30
  [pscustomobject]@{ Status = [int]$response.StatusCode; Json = $json; Headers = $response.Headers }
}

function Error-Code($response) { return $response.Json.errors[0].extensions.code }
function Psql([string]$sql) { (& docker exec $PostgresContainer psql -U fakebook -d $Database -Atc $sql).Trim() }
function Find-Otp([string]$hash) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    for ($i = 0; $i -lt 1000000; $i++) {
      $candidate = $i.ToString('D6')
      $bytes = [Text.Encoding]::UTF8.GetBytes($candidate)
      $candidateHash = [Convert]::ToHexString($sha.ComputeHash($bytes)).ToLowerInvariant()
      if ($candidateHash -eq $hash) { return $candidate }
    }
  } finally { $sha.Dispose() }
  throw 'OTP hash did not match a six-digit code.'
}
function Latest-Otp([string]$email, [int]$type) {
  $hash = Psql "SELECT v.token_hash FROM auth.id_verification v JOIN auth.id_user u ON u.user_id=v.user_id WHERE u.email='$email' AND v.type=$type AND NOT v.is_used ORDER BY v.created_at DESC LIMIT 1;"
  Assert-True ($hash.Length -eq 64) "OTP hash exists for type $type"
  return Find-Otp $hash
}

function Run-MigrationTwice([string]$relativePath, [string]$name) {
  $sql = Get-Content -LiteralPath (Join-Path $repoRoot $relativePath) -Raw
  $sql | docker exec -i $PostgresContainer psql -v ON_ERROR_STOP=1 -U fakebook -d $Database | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "$name migration first run failed." }
  $sql | docker exec -i $PostgresContainer psql -v ON_ERROR_STOP=1 -U fakebook -d $Database | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "$name migration second run failed." }
  Assert-True $true "$name migration is idempotent"
}

Run-MigrationTwice 'fakebookAuth\migrations\20260713_add_gender.sql' 'gender'
Run-MigrationTwice 'fakebookAuth\migrations\20260713_add_valid_date.sql' 'valid_date'
Run-MigrationTwice 'fakebookAuth\migrations\20260714_remove_username.sql' 'remove_username'
Run-MigrationTwice 'fakebookAuth\migrations\20260714_remove_profile_fields.sql' 'remove_profile_fields'
Run-MigrationTwice 'fakebookAuth\migrations\20260714_remove_phone.sql' 'remove_phone'
Run-MigrationTwice 'fakebookAuth\migrations\20260714_rename_schema_to_auth.sql' 'rename_schema_to_auth'
Assert-True ((Psql "SELECT to_regnamespace('auth') IS NOT NULL;") -eq 't') 'Authentication schema is named auth'
Assert-True ((Psql "SELECT to_regnamespace('fb') IS NULL;") -eq 't') 'Legacy fb schema no longer exists'
$removedColumnCount = Psql "SELECT count(*) FROM information_schema.columns WHERE table_schema='auth' AND table_name='id_user' AND column_name IN ('username','phone','dob','display_name','gender');"
Assert-True ($removedColumnCount -eq '0') 'Authentication schema has no phone, username, or SocialGraph profile columns'

$health = Invoke-GraphQl -Url $gateway -Query 'query { health }'
Assert-True ($health.Json.data.health -eq 'ok') 'Gateway health proxies Authentication'
$directHealth = Invoke-GraphQl -Url $auth -Query 'query { health }'
Assert-True ($directHealth.Json.data.health -eq 'ok') 'Direct Authentication health succeeds'

$registerMutation = 'mutation($input:RegisterInput!){register(input:$input){success message}}'
$createUserMutation = 'mutation($input:CreateUserInput!){createUser(input:$input){success userId message}}'
$missingGender = Invoke-GraphQl -Url $gateway -Query $createUserMutation -Variables @{ input = @{ name='Missing Gender'; birthdate='2000-01-01'; location='Ha Noi'; email="missing$suffix@example.com"; password=$password } }
Assert-True ($missingGender.Json.errors.Count -gt 0) 'CreateUser rejects missing gender at GraphQL validation'
$weak = Invoke-GraphQl -Url $auth -Query $registerMutation -Variables @{ input = @{ email="weak$suffix@example.com"; password='short' } }
Assert-True ((Error-Code $weak) -eq 'WEAK_PASSWORD') 'Authentication register rejects weak password'
$invalidEmail = Invoke-GraphQl -Url $auth -Query $registerMutation -Variables @{ input = @{ email='not-an-email'; password=$password } }
Assert-True ($invalidEmail.Json.errors.Count -gt 0) 'Authentication register rejects invalid email'

$maleRegister = Invoke-GraphQl -Url $gateway -Query $createUserMutation -Variables @{ input = @{ name='Nguyen Van A'; birthdate='2000-01-01'; location='Ha Noi'; email=$maleEmail; gender=$true; password=$password } }
Assert-True ($maleRegister.Json.data.createUser.success -eq $true -and $maleRegister.Json.data.createUser.userId) 'Create male user through Gateway and SocialGraph'
$femaleRegister = Invoke-GraphQl -Url $gateway -Query $createUserMutation -Variables @{ input = @{ name='Tran Thi B'; birthdate='2001-02-03'; location='Da Nang'; email=$femaleEmail; gender=$false; password=$password } }
Assert-True ($femaleRegister.Json.data.createUser.success -eq $true -and $femaleRegister.Json.data.createUser.userId) 'Create female user through Gateway and SocialGraph'

$duplicate = Invoke-GraphQl -Url $gateway -Query $createUserMutation -Variables @{ input = @{ name='Duplicate'; birthdate='2000-01-01'; location='Ha Noi'; email=$maleEmail; gender=$true; password=$password } }
Assert-True ($duplicate.Json.data.createUser.success -eq $false) 'CreateUser rejects duplicate email and rolls back SocialGraph user'
$loginMutation = 'mutation($input:LoginInput!){login(input:$input){accessToken refreshToken refreshTokenExpiresAt user{userId email validDate status}}}'
$unverified = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{ input = @{ identifier=$maleEmail; password=$password } }
Assert-True ((Error-Code $unverified) -eq 'EMAIL_UNVERIFIED') 'Unverified login rejected'
$usernameStyleLogin = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{ input = @{ identifier="authmale$suffix"; password=$password } }
Assert-True ((Error-Code $usernameStyleLogin) -eq 'INVALID_CREDENTIALS') 'Authentication does not support username login'

$verifyMutation = 'mutation($input:VerifyEmailInput!){verifyEmail(input:$input){success message}}'
$maleOtp = Latest-Otp $maleEmail 1
$femaleOtp = Latest-Otp $femaleEmail 1
$wrongOtp = if ($maleOtp -eq '000000') { '999999' } else { '000000' }
$invalidVerification = Invoke-GraphQl -Url $gateway -Query $verifyMutation -Variables @{ input=@{identifier=$maleEmail;otp=$wrongOtp} }
Assert-True ((Error-Code $invalidVerification) -eq 'INVALID_OR_EXPIRED_VERIFICATION_CODE') 'Invalid verification OTP rejected'

$expiredEmail = "expired$suffix@example.com"
$expiredRegister = Invoke-GraphQl -Url $auth -Query $registerMutation -Variables @{ input = @{ email=$expiredEmail; password=$password } }
Assert-True ($expiredRegister.Json.data.register.success -eq $true) 'Direct Authentication register succeeds'
$expiredOtp = Latest-Otp $expiredEmail 1
Psql "UPDATE auth.id_verification SET expires_at=now()-interval '1 minute' WHERE verification_id=(SELECT v.verification_id FROM auth.id_verification v JOIN auth.id_user u ON u.user_id=v.user_id WHERE u.email='$expiredEmail' AND v.type=1 ORDER BY v.created_at DESC LIMIT 1);" | Out-Null
$expiredVerification = Invoke-GraphQl -Url $auth -Query $verifyMutation -Variables @{ input=@{identifier=$expiredEmail;otp=$expiredOtp} }
Assert-True ((Error-Code $expiredVerification) -eq 'INVALID_OR_EXPIRED_VERIFICATION_CODE') 'Expired verification OTP rejected'
$wrongOtp = $null; $expiredOtp = $null

Assert-True ((Invoke-GraphQl -Url $gateway -Query $verifyMutation -Variables @{ input=@{identifier=$maleEmail;otp=$maleOtp} }).Json.data.verifyEmail.success) 'Verify male email'
Assert-True ((Invoke-GraphQl -Url $gateway -Query $verifyMutation -Variables @{ input=@{identifier=$femaleEmail;otp=$femaleOtp} }).Json.data.verifyEmail.success) 'Verify female email'
$maleOtp = $null; $femaleOtp = $null

$femaleSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$femaleLogin = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{ input=@{identifier=$femaleEmail;password=$password} } -Session $femaleSession
$femaleOldRefresh = $femaleSession.Cookies.GetCookies($gatewayOrigin)['fb_refresh'].Value
$femaleRefresh = Invoke-GraphQl -Url $gateway -Query 'mutation{refreshToken{accessToken}}' -Session $femaleSession
$femaleToken = $femaleRefresh.Json.data.refreshToken.accessToken
$reuseSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$gatewayUri = [Uri]$gatewayOrigin
$reuseSession.Cookies.Add($gatewayUri, [System.Net.Cookie]::new('fb_refresh', $femaleOldRefresh, '/', $gatewayUri.Host))
$reuse = Invoke-GraphQl -Url $gateway -Query 'mutation{refreshToken{accessToken}}' -Session $reuseSession
Assert-True ((Error-Code $reuse) -in @('REFRESH_TOKEN_REUSE_DETECTED', 'INVALID_REFRESH_TOKEN')) 'Replaced refresh token reuse rejected'
$femaleAfterReuse = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -Token $femaleToken -Session $femaleSession
Assert-True ($femaleAfterReuse.Status -eq 401 -or (Error-Code $femaleAfterReuse) -eq 'UNAUTHENTICATED') 'Refresh token reuse revokes account sessions'
$femaleOldRefresh = $null; $femaleToken = $null

$session1 = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$login1 = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{ input=@{identifier=$maleEmail;password=$password} } -Session $session1
$token1 = $login1.Json.data.login.accessToken
Assert-True (-not [string]::IsNullOrWhiteSpace($token1)) 'Login returns access token'
Assert-True ($login1.Json.data.login.refreshToken -eq $null) 'Gateway scrubs raw refresh token'
Assert-True ($login1.Json.data.login.user.email -eq $maleEmail) 'Login user includes Auth identity fields'
Assert-True ($session1.Cookies.GetCookies($gatewayOrigin)['fb_refresh'].HttpOnly) 'Gateway sets HttpOnly refresh cookie'

$me = Invoke-GraphQl -Url $gateway -Query 'query{me{userId email validDate status}}' -Token $token1 -Session $session1
Assert-True ($me.Json.data.me.email -eq $maleEmail) 'Authenticated me includes Auth identity fields'
$active = Invoke-GraphQl -Url $gateway -Query 'query{mySessions{sessionId isCurrent revokedAt}}' -Token $token1 -Session $session1
Assert-True ($active.Json.data.mySessions.Count -eq 1 -and $active.Json.data.mySessions[0].isCurrent) 'mySessions returns current session'

$oldCookie = $session1.Cookies.GetCookies($gatewayOrigin)['fb_refresh'].Value
$refresh = Invoke-GraphQl -Url $gateway -Query 'mutation{refreshToken{accessToken refreshToken user{userId}}}' -Session $session1
$token1 = $refresh.Json.data.refreshToken.accessToken
$newCookie = $session1.Cookies.GetCookies($gatewayOrigin)['fb_refresh'].Value
Assert-True (-not [string]::IsNullOrWhiteSpace($token1) -and $newCookie -ne $oldCookie) 'Refresh rotates token and cookie'
Assert-True ($refresh.Json.data.refreshToken.refreshToken -eq $null) 'Refresh response scrubs raw refresh token'
$oldCookie = $null; $newCookie = $null

$session2 = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$login2 = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{ input=@{identifier=$maleEmail;password=$password} } -Session $session2
$token2 = $login2.Json.data.login.accessToken
$active = Invoke-GraphQl -Url $gateway -Query 'query{mySessions{sessionId isCurrent}}' -Token $token1 -Session $session1
Assert-True ($active.Json.data.mySessions.Count -ge 2) 'Multiple active sessions listed'
$other = $active.Json.data.mySessions | Where-Object { -not $_.isCurrent } | Select-Object -First 1
$logoutOther = Invoke-GraphQl -Url $gateway -Query 'mutation($input:LogoutSessionInput!){logoutSession(input:$input){success}}' -Variables @{input=@{sessionId=$other.sessionId}} -Token $token1 -Session $session1
Assert-True ($logoutOther.Json.data.logoutSession.success) 'Logout individual session'
$revokedCall = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -Token $token2 -Session $session2
Assert-True ($revokedCall.Status -eq 401 -or (Error-Code $revokedCall) -eq 'UNAUTHENTICATED') 'Revoked session access token rejected'
$history = Invoke-GraphQl -Url $gateway -Query 'query{mySessionHistory{sessionId revokedAt revocationReason isCurrent}}' -Token $token1 -Session $session1
Assert-True (($history.Json.data.mySessionHistory | Where-Object { $_.sessionId -eq $other.sessionId -and $_.revokedAt }).Count -eq 1) 'mySessionHistory includes revoked session'

$change = Invoke-GraphQl -Url $gateway -Query 'mutation($input:ChangePasswordInput!){changePassword(input:$input){success}}' -Variables @{input=@{currentPassword=$password;newPassword=$changedPassword}} -Token $token1 -Session $session1
Assert-True ($change.Json.data.changePassword.success) 'Change password succeeds'
$oldPasswordLogin = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{input=@{identifier=$maleEmail;password=$password}}
Assert-True ((Error-Code $oldPasswordLogin) -eq 'INVALID_CREDENTIALS') 'Old password rejected after change'

$requestReset = Invoke-GraphQl -Url $gateway -Query 'mutation($input:RequestPasswordResetInput!){requestPasswordReset(input:$input){success}}' -Variables @{input=@{identifier=$maleEmail}}
Assert-True ($requestReset.Json.data.requestPasswordReset.success) 'Request password reset succeeds'
$resetOtp = Latest-Otp $maleEmail 3
$reset = Invoke-GraphQl -Url $gateway -Query 'mutation($input:ResetPasswordInput!){resetPassword(input:$input){success}}' -Variables @{input=@{identifier=$maleEmail;otp=$resetOtp;newPassword=$resetPassword}}
$resetOtp = $null
Assert-True ($reset.Json.data.resetPassword.success) 'Reset password succeeds'
$oldSessionAfterReset = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -Token $token1 -Session $session1
Assert-True ($oldSessionAfterReset.Status -eq 401 -or (Error-Code $oldSessionAfterReset) -eq 'UNAUTHENTICATED') 'Password reset revokes existing sessions'

$session3 = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$login3 = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{input=@{identifier=$maleEmail;password=$resetPassword}} -Session $session3
$token3 = $login3.Json.data.login.accessToken
Assert-True (-not [string]::IsNullOrWhiteSpace($token3)) 'Login succeeds with reset password'
$spoof = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -ExtraHeaders @{'X-User-Id'='1';'X-Session-Id'='1';'X-Gateway-Secret'='spoof'}
Assert-True ((Error-Code $spoof) -eq 'UNAUTHENTICATED') 'Spoofed trusted headers do not authenticate'

$currentSessions = Invoke-GraphQl -Url $gateway -Query 'query{mySessions{sessionId isCurrent}}' -Token $token3 -Session $session3
$currentSessionId = ($currentSessions.Json.data.mySessions | Where-Object isCurrent | Select-Object -First 1).sessionId
$logoutCurrent = Invoke-GraphQl -Url $gateway -Query 'mutation($input:LogoutSessionInput!){logoutSession(input:$input){success}}' -Variables @{input=@{sessionId=$currentSessionId}} -Token $token3 -Session $session3
Assert-True ($logoutCurrent.Json.data.logoutSession.success) 'Current-session logoutSession succeeds'
$currentCookie = $session3.Cookies.GetCookies($gatewayOrigin)['fb_refresh']
Assert-True ($null -eq $currentCookie -or [string]::IsNullOrEmpty($currentCookie.Value)) 'Current-session logoutSession clears cookie'
$currentRevoked = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -Token $token3 -Session $session3
Assert-True ($currentRevoked.Status -eq 401 -or (Error-Code $currentRevoked) -eq 'UNAUTHENTICATED') 'Current-session access token rejected after logoutSession'

$session4 = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$login4 = Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{input=@{identifier=$maleEmail;password=$resetPassword}} -Session $session4
$token4 = $login4.Json.data.login.accessToken
$logout = Invoke-GraphQl -Url $gateway -Query 'mutation{logout{success}}' -Token $token4 -Session $session4
Assert-True ($logout.Json.data.logout.success) 'Inputless browser logout succeeds'
$logoutCookie = $session4.Cookies.GetCookies($gatewayOrigin)['fb_refresh']
Assert-True ($null -eq $logoutCookie -or [string]::IsNullOrEmpty($logoutCookie.Value)) 'Logout clears refresh cookie'

$session5 = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$session6 = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$token5 = (Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{input=@{identifier=$maleEmail;password=$resetPassword}} -Session $session5).Json.data.login.accessToken
$token6 = (Invoke-GraphQl -Url $gateway -Query $loginMutation -Variables @{input=@{identifier=$maleEmail;password=$resetPassword}} -Session $session6).Json.data.login.accessToken
$logoutAll = Invoke-GraphQl -Url $gateway -Query 'mutation{logoutAll{success}}' -Token $token5 -Session $session5
Assert-True ($logoutAll.Json.data.logoutAll.success) 'logoutAll succeeds'
$afterLogoutAll1 = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -Token $token5 -Session $session5
$afterLogoutAll2 = Invoke-GraphQl -Url $gateway -Query 'query{me{userId}}' -Token $token6 -Session $session6
$firstLoggedOut = $afterLogoutAll1.Status -eq 401 -or (Error-Code $afterLogoutAll1) -eq 'UNAUTHENTICATED'
$secondLoggedOut = $afterLogoutAll2.Status -eq 401 -or (Error-Code $afterLogoutAll2) -eq 'UNAUTHENTICATED'
Assert-True ($firstLoggedOut -and $secondLoggedOut) 'logoutAll revokes every active session'

$internalUserId = 600000000000000000 + $suffix
$internalEmail = "internal$suffix@example.com"
$internalBody = @{
  userId = $internalUserId
  email = $internalEmail
  password = $password
} | ConvertTo-Json -Compress
$missingInternalSecret = Invoke-WebRequest "$authOrigin/internal/users" -Method Post -ContentType 'application/json' -Body $internalBody -SkipHttpErrorCheck
Assert-True ($missingInternalSecret.StatusCode -eq 400) '/internal/users rejects missing secret'
$wrongInternalSecret = Invoke-WebRequest "$authOrigin/internal/users" -Method Post -ContentType 'application/json' -Headers @{'X-Gateway-Secret'='wrong'} -Body $internalBody -SkipHttpErrorCheck
Assert-True ($wrongInternalSecret.StatusCode -eq 400) '/internal/users rejects wrong secret'
$createdInternal = Invoke-WebRequest "$authOrigin/internal/users" -Method Post -ContentType 'application/json' -Headers @{'X-Gateway-Secret'=$GatewaySecret} -Body $internalBody -SkipHttpErrorCheck
Assert-True ($createdInternal.StatusCode -eq 200) '/internal/users accepts correct secret'
Assert-True ((Psql "SELECT count(*) FROM auth.id_user WHERE email='$internalEmail';") -eq '1') '/internal/users persists the Auth identity'

$paymentQuery = 'query($userId:ID!){paymentPremiumState(userId:$userId){userId validDate}}'
$paymentMutation = 'mutation($input:SetPaymentValidDateInput!){setPaymentValidDate(input:$input){userId validDate}}'
$paymentWrong = Invoke-GraphQl -Url $auth -Query $paymentQuery -Variables @{userId="$internalUserId"} -ExtraHeaders @{'X-Payment-Secret'='wrong'}
Assert-True ((Error-Code $paymentWrong) -eq 'FORBIDDEN') 'Payment Premium query rejects wrong secret'
$laterValidDate = [DateTimeOffset]::UtcNow.AddDays(30).ToString('o')
$paymentSet = Invoke-GraphQl -Url $auth -Query $paymentMutation -Variables @{input=@{userId="$internalUserId";validDate=$laterValidDate}} -ExtraHeaders @{'X-Payment-Secret'=$PaymentSecret}
Assert-True ([DateTimeOffset]::Parse($paymentSet.Json.data.setPaymentValidDate.validDate) -eq [DateTimeOffset]::Parse($laterValidDate)) 'Payment sets Premium validDate'
$updatedAfterExtension = Psql "SELECT updated_at::text FROM auth.id_user WHERE user_id=$internalUserId;"
$earlierValidDate = [DateTimeOffset]::UtcNow.AddDays(10).ToString('o')
$paymentRetry = Invoke-GraphQl -Url $auth -Query $paymentMutation -Variables @{input=@{userId="$internalUserId";validDate=$earlierValidDate}} -ExtraHeaders @{'X-Payment-Secret'=$PaymentSecret}
Assert-True ([DateTimeOffset]::Parse($paymentRetry.Json.data.setPaymentValidDate.validDate) -eq [DateTimeOffset]::Parse($laterValidDate)) 'Payment retry cannot shorten Premium validity'
$updatedAfterNoOpRetry = Psql "SELECT updated_at::text FROM auth.id_user WHERE user_id=$internalUserId;"
Assert-True ($updatedAfterNoOpRetry -eq $updatedAfterExtension) 'Payment no-op retry does not mutate updated_at'
$paymentRead = Invoke-GraphQl -Url $auth -Query $paymentQuery -Variables @{userId="$internalUserId"} -ExtraHeaders @{'X-Payment-Secret'=$PaymentSecret}
Assert-True ([DateTimeOffset]::Parse($paymentRead.Json.data.paymentPremiumState.validDate) -eq [DateTimeOffset]::Parse($laterValidDate)) 'Payment reads persisted Premium validity'

$internalWrong = Invoke-GraphQl -Url $auth -Query 'query($input:GatewaySessionValidationInput!){validateGatewaySession(input:$input){isValid}}' -Variables @{input=@{userId=1;sessionId=1}} -ExtraHeaders @{'X-Gateway-Secret'='wrong'}
Assert-True ((Error-Code $internalWrong) -eq 'FORBIDDEN') 'Internal session validation rejects wrong secret'

[pscustomobject]@{ Passed = $assertions.Count; Assertions = $assertions }
