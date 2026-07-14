# Hướng Dẫn Agent Cho Fakebook Authentication Subgraph

File này là tài liệu làm việc cho developer và AI Agent khi chỉnh sửa hoặc tích hợp Fakebook Authentication subgraph.

Consumer quan trọng nhất trong giai đoạn tiếp theo là GraphQL Federation Gateway. Gateway nên coi subgraph này là nơi sở hữu toàn bộ nghiệp vụ định danh: tài khoản, credential, session, refresh token rotation, OTP, login/logout và các workflow xác thực.

## Tổng Quan Dự Án

- Loại project: .NET 8 ASP.NET Core GraphQL service.
- Thư viện GraphQL: HotChocolate.
- Database: PostgreSQL.
- Data access: Dapper + Npgsql.
- Hash password: BCrypt.
- Access token: JWT HS256 tự build trong project.
- Refresh token trong DB: chỉ lưu SHA-256 hash, không lưu raw token.
- Mô hình refresh token với Gateway: Auth subgraph trả token + cookie instruction; Gateway là nơi set/clear cookie thật cho browser.
- Gửi email: SMTP qua `SmtpEmailSender`.
- Endpoint chính: `/graphql`.
- Route `/` redirect sang `/graphql`.

## Các File Quan Trọng

- `Program.cs`: đăng ký service, validate options, đăng ký GraphQL, middleware correlation id.
- `Configuration/Configuration.cs`: cấu hình JWT, Auth, SMTP, Snowflake ID.
- `GraphQL/GraphQLSchema.cs`: danh sách query/mutation GraphQL.
- `GraphQL/GraphQLContracts.cs`: input/output contract của GraphQL.
- `Services/AuthService.cs`: nghiệp vụ xác thực chính.
- `Services/SmtpEmailSender.cs`: gửi OTP qua SMTP.
- `Security/SecurityServices.cs`: hash password, tạo/validate JWT, tạo refresh token, Snowflake ID, OTP.
- `Repositories/Repositories.cs`: truy cập PostgreSQL.
- `Models/DataModels.cs`: model nội bộ và constants.
- `schema.sql`: schema tham chiếu khi tạo database mới.

Không commit secret. `appsettings.json` và `appsettings.Development.json` ở local có thể chứa DB password, Gmail app password, JWT signing key, nên phải coi là dữ liệu nhạy cảm.

## Cấu Hình Runtime

Connection string được đọc theo thứ tự:

1. `ConnectionStrings:DefaultConnection`
2. `POSTGRES_CONNECTION_STRING`

Cấu hình JWT bắt buộc:

```text
Jwt__SigningKey
```

`Jwt:SigningKey` phải dài tối thiểu 32 bytes.

Các environment variable hữu ích:

```text
ConnectionStrings__DefaultConnection
POSTGRES_CONNECTION_STRING
Jwt__Issuer
Jwt__Audience
Jwt__SigningKey
Jwt__AccessTokenMinutes
Auth__RefreshTokenDays
Auth__EmailVerificationMinutes
Auth__PasswordResetMinutes
Auth__OtpCooldownSeconds
Auth__OtpFailureLimit
Auth__OtpFailureWindowMinutes
Auth__OtpResendLimit
Auth__OtpResendWindowMinutes
Auth__LoginFailureLimit
Auth__LoginFailureWindowMinutes
Auth__RefreshTokenCookieName
Auth__RefreshTokenCookiePath
Auth__RefreshTokenCookieSameSite
Auth__RefreshTokenCookieHttpOnly
Auth__RefreshTokenCookieSecure
Gateway__InternalSharedSecret
Payment__InternalSharedSecret
Smtp__Enabled
Smtp__Host
Smtp__Port
Smtp__EnableSsl
Smtp__Username
Smtp__Password
Smtp__FromEmail
Smtp__FromName
Snowflake__WorkerId
```

Giá trị mặc định trong code:

```text
RefreshTokenDays = 30
EmailVerificationMinutes = 15
PasswordResetMinutes = 15
OtpCooldownSeconds = 60
OtpFailureLimit = 5
OtpFailureWindowMinutes = 15
OtpResendLimit = 3
OtpResendWindowMinutes = 15
LoginFailureLimit = 5
LoginFailureWindowMinutes = 15
RefreshTokenCookieName = fb_refresh
RefreshTokenCookiePath = /
RefreshTokenCookieSameSite = Lax
RefreshTokenCookieHttpOnly = true
RefreshTokenCookieSecure = true
```

Nếu dùng `Auth__RefreshTokenCookieSameSite=None` thì bắt buộc `Auth__RefreshTokenCookieSecure=true`.

## Ghi Chú Database

Schema PostgreSQL là `fb`.

Các bảng chính:

- `fb.id_user`: tài khoản định danh phục vụ authentication.
- `fb.id_credential`: credential đăng nhập, hiện dùng password hash.
- `fb.id_session`: trạng thái session, refresh token hash hiện tại, revoke state.
- `fb.id_session_refresh_token`: lịch sử refresh token để phát hiện reuse.
- `fb.id_verification`: OTP verification.
- `fb.id_audit_log`: audit log bảo mật.
- `fb.id_role`, `fb.id_permission`, `fb.id_role_permission`, `fb.id_user_role`: khung role/permission.
- `fb.id_mfa_method`: khung MFA.

Authentication chỉ định danh bằng email và hiện không có phone identifier. SocialGraph sở hữu riêng username, name, birthdate, gender, location và toàn bộ profile data khác. Migration history được giữ bất biến và database hiện có phải đạt thứ tự cuối cùng sau:

```text
migrations/20260713_add_gender.sql
migrations/20260713_add_valid_date.sql
migrations/20260714_remove_username.sql
migrations/20260714_remove_profile_fields.sql
migrations/20260714_remove_phone.sql
```

`20260713_add_gender.sql` được giữ lại như migration history và bị supersede bởi `20260714_remove_profile_fields.sql`. Nếu rolling deployment, deploy Auth email-only/profile-free này, drain toàn bộ Auth instance cũ, rồi mới chạy các migration destructive. Database mới dùng `schema.sql`, vốn đã không còn phone hay profile column.

Giá trị `id_user.status`:

```text
1 = active
2 = disabled
3 = deleted
4 = unverified
```

Giá trị verification type:

```text
1 = email verification
3 = password reset
```

Giá trị credential provider:

```text
1 = password
```

Lưu refresh token:

- Raw refresh token chỉ xuất hiện khi login/refresh thành công.
- DB chỉ lưu SHA-256 hex hash.
- `id_session.refresh_token` lưu hash của refresh token hiện tại.
- `id_session_refresh_token` lưu hash hiện tại và các token đã bị thay thế.
- Nếu refresh token cũ đã bị rotate được dùng lại trong lúc session vẫn active, coi như token bị leak/replay và revoke toàn bộ session của user.
- Nếu token thuộc session đã revoke/expired thì chỉ trả `INVALID_REFRESH_TOKEN`, ghi audit `REVOKED_REFRESH_TOKEN_USED`, không logout toàn account.

## Observability

Mỗi request có `X-Correlation-ID`.

Cơ chế:

- Nếu request có header `X-Correlation-ID`, service dùng lại giá trị đó.
- Nếu không có, service tạo correlation id mới.
- Response luôn có header `X-Correlation-ID`.
- Log scope có correlation id.

Auth service log các sự kiện quan trọng:

- login thành công
- refresh token rotation
- phát hiện refresh token reuse
- reject token của session đã revoke/expired
- OTP failure/rate limit
- logout/logout all/logout session
- reset password/change password

## Access Token

Access token là JWT HS256 do `TokenService` tạo.

Claims chính:

```text
iss
aud
sub
user_id
name
iat
nbf
exp
jti
sid
```

`sid` là session id, được thêm vào token khi login/refresh.

Các operation cần auth trong subgraph này kiểm tra:

1. Có `Authorization: Bearer <accessToken>`.
2. JWT signature, issuer, audience, expiry, not-before hợp lệ.
3. User tồn tại và đang active.
4. Nếu token có `sid`, session phải còn active và chưa hết hạn.

Vì vậy access token của session đã logout/revoke sẽ bị từ chối bởi các operation protected của Auth subgraph, kể cả khi JWT chưa hết hạn.

## Hướng Dẫn Cho Gateway Và Federation

Gateway nên là public entry point duy nhất cho frontend.

Phân chia trách nhiệm đề xuất:

- Auth Subgraph sở hữu credential, OTP, session, JWT issuing, refresh token rotation và cookie instruction.
- Gateway sở hữu cookie thật trên browser và public response shaping.
- Các subgraph khác không đọc cookie browser và không xử lý refresh token.
- Các subgraph khác chỉ tin identity context do Gateway truyền qua boundary nội bộ.

Flow protected request đề xuất:

```text
Frontend -> Gateway protected operation
Gateway validate access token local
Gateway lấy user_id và sid
Gateway có thể check active session với Auth Subgraph hoặc cache ngắn hạn
Gateway forward request sang subgraph khác với internal identity context
```

Header nội bộ gợi ý nếu Gateway gọi subgraph qua HTTP:

```text
X-User-Id
X-Session-Id
X-Correlation-ID
X-Refresh-Token
X-Gateway-Secret
X-Fakebook-Refresh-Cookie-Instruction
```

Không cho browser tự set các identity header này. Gateway phải strip header từ public request rồi tự tạo lại ở internal request.
`X-Refresh-Token`, `X-Gateway-Secret` và `X-Fakebook-Refresh-Cookie-Instruction` là header nội bộ. Browser không được phép tự gửi các header này.
Gateway cũng strip header legacy `X-Username` nhưng không tạo lại hoặc forward; downstream service lấy username/profile từ SocialGraph.

Flow cookie đề xuất cho Gateway:

```text
login:
  Gateway gọi Auth login
  Auth trả accessToken, refreshToken, refreshTokenCookie
  Gateway set HttpOnly refresh cookie theo refreshTokenCookie
  Gateway nên tránh trả raw refreshToken về JavaScript nếu có thể
  Gateway trả accessToken và user data về frontend

refresh:
  Gateway đọc refresh token từ HttpOnly cookie
  Gateway gọi Auth refreshToken
  Auth rotate refresh token và trả SET cookie instruction mới
  Gateway set cookie mới
  Gateway trả accessToken mới

logout:
  Gateway đọc refresh token từ cookie
  Gateway gọi Auth logout
  Gateway clear cookie theo instruction

logoutAll:
  Gateway gọi Auth logoutAll với bearer access token
  Gateway clear cookie của browser hiện tại

logoutSession:
  Gateway gọi Auth logoutSession với bearer access token
  Nếu response có cookie instruction CLEAR thì clear cookie hiện tại
  Nếu refreshTokenCookie null thì không đụng cookie hiện tại
```

`LoginPayload` hiện vẫn có cả `refreshToken` và `refreshTokenCookie.value`. Gateway phải coi giá trị này là cực kỳ nhạy cảm. Public response trả về frontend nên bỏ raw refresh token nếu thiết kế cho phép.

## Cookie Instruction Contract

GraphQL type:

```graphql
type GatewayCookieInstruction {
  operation: String!
  name: String!
  value: String
  path: String!
  sameSite: String!
  httpOnly: Boolean!
  secure: Boolean!
  maxAgeSeconds: Int!
  expiresAt: DateTime
}
```

Operation hiện có:

```text
SET
CLEAR
```

Với `SET`:

- `value` là raw refresh token.
- `maxAgeSeconds` bằng `Auth.RefreshTokenDays` quy đổi sang giây.
- `expiresAt` là thời điểm refresh token hết hạn.

Với `CLEAR`:

- `value` là chuỗi rỗng.
- `maxAgeSeconds` là `0`.
- `expiresAt` là Unix epoch.

Auth cũng ghi cùng cookie instruction dưới dạng base64 JSON vào HTTP response header nội bộ:

```text
X-Fakebook-Refresh-Cookie-Instruction
```

Gateway nên consume header này, set hoặc clear cookie thật trên browser, và không forward header nội bộ này về public client. Cơ chế này giúp Gateway vẫn quản lý cookie đúng ngay cả khi frontend không select `refreshTokenCookie` trong GraphQL response.

## GraphQL Queries

### health

Health check public.

```graphql
query Health {
  health
}
```

Kết quả:

```json
{
  "data": {
    "health": "ok"
  }
}
```

### me

Yêu cầu:

```text
Authorization: Bearer <accessToken>
```

Validate JWT, trạng thái user và active session.

```graphql
query Me {
  me {
    userId
    email
    validDate
    status
  }
}
```

### mySessions

Yêu cầu bearer access token.

Trả danh sách session đang active của user hiện tại.

```graphql
query MySessions {
  mySessions {
    sessionId
    deviceName
    os
    browser
    ipAddress
    expiresAt
    createdAt
    lastSeenAt
    revocationReason
    revokedAt
    isCurrent
  }
}
```

Với session active, `revokedAt` và `revocationReason` thường là null.

### mySessionHistory

Yêu cầu bearer access token.

Trả cả active session và revoked session của user hiện tại.

```graphql
query MySessionHistory {
  mySessionHistory {
    sessionId
    deviceName
    os
    browser
    ipAddress
    expiresAt
    createdAt
    lastSeenAt
    revocationReason
    revokedAt
    isCurrent
  }
}
```

### validateGatewaySession

Validate session nội bộ, chỉ dành cho Gateway gọi Auth.

Yêu cầu:

```text
X-Gateway-Secret: <Gateway__InternalSharedSecret>
```

```graphql
query ValidateGatewaySession($input: GatewaySessionValidationInput!) {
  validateGatewaySession(input: $input) {
    isValid
    userId
    sessionId
    status
    expiresAt
  }
}
```

Lưu ý:

- Field này chỉ dùng cho traffic Gateway -> Auth.
- Gateway nên mark field này là `@internal` trong Fusion source schema extensions để không expose public.
- Trả `isValid = false` nếu user không tồn tại, user không active, hoặc session đã revoke/expired.
- Thiếu hoặc sai `X-Gateway-Secret` sẽ trả GraphQL error code `FORBIDDEN`.

## Internal REST APIs

### POST /internal/users

API nội bộ để SocialGraph tạo identity trong Auth bằng canonical user id do SocialGraph sinh ra.

Yêu cầu:

```text
X-Gateway-Secret: <Gateway__InternalSharedSecret>
```

Payload:

```json
{
  "userId": 1234567890123456789,
  "email": "a@example.com",
  "password": "at-least-8-chars"
}
```

Hành vi:

- Tạo `id_user` với đúng `userId` được truyền vào.
- Tạo password credential và OTP verify email.
- Giữ account ở trạng thái `unverified` cho đến khi gọi `verifyEmail`.
- Không nhận hoặc lưu username, display name, DOB hay gender. SocialGraph sở hữu các field đó.
- Thiếu hoặc sai `X-Gateway-Secret` sẽ bị reject.

## GraphQL Mutations

### register

Đây là mutation Auth-only dùng cho direct test/backward compatibility. Gateway mark nó `@internal`; frontend đăng ký qua SocialGraph `createUser`.

Mutation tạo account unverified với ID do Auth tự sinh và tạo OTP verify email.

```graphql
mutation Register($input: RegisterInput!) {
  register(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "email": "quan@example.com",
    "password": "Password123!"
  }
}
```

Lưu ý:

- Email được normalize về lower-case.
- Password tối thiểu 8 ký tự.
- User mới có `status = 4` (unverified).
- Nếu SMTP enabled, OTP sẽ được gửi qua email.
- Nếu SMTP disabled, dev phải verify thủ công bằng DB/test flow.

### verifyEmail

Kích hoạt account bằng OTP 6 chữ số.

```graphql
mutation VerifyEmail($input: VerifyEmailInput!) {
  verifyEmail(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com",
    "otp": "123456"
  }
}
```

Lưu ý:

- `identifier` là email tài khoản. Authentication không hỗ trợ login bằng username.
- OTP bắt buộc đúng 6 chữ số.
- Nhập sai OTP được audit và rate limit.
- Verify thành công sẽ mark OTP used và activate account.

### resendEmailVerification

Gửi lại OTP verify email.

```graphql
mutation ResendEmailVerification($input: ResendEmailVerificationInput!) {
  resendEmailVerification(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com"
  }
}
```

Lưu ý:

- Chỉ hữu ích với user chưa verify.
- Có cooldown qua `Auth.OtpCooldownSeconds`.
- Có resend rate limit qua `Auth.OtpResendLimit` và `Auth.OtpResendWindowMinutes`.
- OTP cũ cùng type sẽ bị mark used trước khi tạo OTP mới.

### login

Đăng nhập bằng email + password và tạo session mới. `identifier` phải chứa email; hiện chưa hỗ trợ đăng nhập bằng phone.

```graphql
mutation Login($input: LoginInput!) {
  login(input: $input) {
    accessToken
    refreshToken
    refreshTokenExpiresAt
    refreshTokenCookie {
      operation
      name
      value
      path
      sameSite
      httpOnly
      secure
      maxAgeSeconds
      expiresAt
    }
    user {
      userId
      email
      validDate
      status
    }
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com",
    "password": "Password123!"
  }
}
```

Lưu ý:

- Account phải verified và active.
- Ghi audit `LOGIN_SUCCESS`.
- Ghi audit `LOGIN_FAILURE` nếu user không tồn tại hoặc password sai.
- Login failure được rate limit theo identifier và IP nếu có IP.
- Tạo row trong `id_session`.
- Chỉ lưu refresh token hash trong DB.
- Access token có claim `sid`.
- Trả raw refresh token và cookie instruction cho Gateway.

### refreshToken

Rotate refresh token và cấp access token mới.

```graphql
mutation RefreshToken($input: RefreshTokenInput!) {
  refreshToken(input: $input) {
    accessToken
    refreshToken
    refreshTokenExpiresAt
    refreshTokenCookie {
      operation
      name
      value
      maxAgeSeconds
      expiresAt
    }
    user {
      userId
      email
      validDate
    }
  }
}
```

Variables:

```json
{
  "input": {
    "refreshToken": "<raw-refresh-token>"
  }
}
```

Lưu ý:

- Nhận raw refresh token.
- Gateway có thể bỏ `input.refreshToken` nếu gửi raw token qua header nội bộ `X-Refresh-Token`.
- Hash token rồi tìm active session.
- Thành công thì rotate token ngay.
- Ghi token cũ vào token history với `replaced_at`.
- Ghi audit `REFRESH_TOKEN_ROTATED`.
- Nếu token cũ đã bị thay thế được dùng lại khi session vẫn active, ghi `REFRESH_TOKEN_REUSE_DETECTED` và revoke toàn bộ session.
- Nếu token thuộc session đã revoke/expired, trả `INVALID_REFRESH_TOKEN`, ghi `REVOKED_REFRESH_TOKEN_USED`, không revoke toàn account.

### logout

Logout bằng refresh token.

```graphql
mutation Logout($input: LogoutInput!) {
  logout(input: $input) {
    success
    message
    refreshTokenCookie {
      operation
      name
      value
      maxAgeSeconds
    }
  }
}
```

Variables:

```json
{
  "input": {
    "refreshToken": "<raw-refresh-token>"
  }
}
```

Lưu ý:

- Nếu token active, revoke session với reason `LOGOUT`.
- Gateway có thể bỏ `input.refreshToken` nếu gửi raw token qua header nội bộ `X-Refresh-Token`.
- Luôn trả success.
- Trả cookie instruction `CLEAR`.

### logoutAll

Revoke toàn bộ session của user hiện tại.

Yêu cầu bearer access token.

```graphql
mutation LogoutAll {
  logoutAll {
    success
    message
    refreshTokenCookie {
      operation
      name
      maxAgeSeconds
    }
  }
}
```

Lưu ý:

- Revoke mọi active session với reason `LOGOUT_ALL`.
- Trả cookie instruction `CLEAR` cho browser hiện tại.

### logoutSession

Revoke một session cụ thể thuộc user hiện tại.

Yêu cầu bearer access token.

```graphql
mutation LogoutSession($input: LogoutSessionInput!) {
  logoutSession(input: $input) {
    success
    message
    refreshTokenCookie {
      operation
      name
      value
      maxAgeSeconds
    }
  }
}
```

Variables:

```json
{
  "input": {
    "sessionId": 1234567890
  }
}
```

Lưu ý:

- Revoke session với reason `SESSION_REVOKED_BY_USER`.
- Nếu revoke chính session hiện tại, response có cookie instruction `CLEAR`.
- Nếu revoke session khác, `refreshTokenCookie` là null và Gateway không được clear cookie hiện tại.
- Access token của session bị revoke sẽ bị reject bởi protected operations.

### requestPasswordReset

Tạo và gửi OTP reset password nếu account active tồn tại.

```graphql
mutation RequestPasswordReset($input: RequestPasswordResetInput!) {
  requestPasswordReset(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com"
  }
}
```

Lưu ý:

- Luôn trả message generic để tránh account enumeration.
- Chỉ account active mới nhận OTP.
- Có OTP cooldown và resend rate limit.
- Ghi audit `OTP_RESENT` cho password reset OTP.

### resetPassword

Reset password bằng password reset OTP.

```graphql
mutation ResetPassword($input: ResetPasswordInput!) {
  resetPassword(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com",
    "otp": "123456",
    "newPassword": "NewPassword123!"
  }
}
```

Lưu ý:

- Chỉ account active mới reset được password.
- OTP sai được audit và rate limit.
- Thành công thì update password credential.
- Mark OTP used.
- Revoke toàn bộ session của user với reason `PASSWORD_RESET`.
- Ghi audit `OTP_VERIFIED` và `PASSWORD_RESET`.

### changePassword

Đổi password cho user đã authenticated.

Yêu cầu bearer access token.

```graphql
mutation ChangePassword($input: ChangePasswordInput!) {
  changePassword(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "currentPassword": "Password123!",
    "newPassword": "ChangedPassword123!"
  }
}
```

Lưu ý:

- Current password phải đúng.
- New password tối thiểu 8 ký tự.
- New password phải khác password hiện tại.
- Revoke các session khác với reason `PASSWORD_CHANGED`.
- Giữ session hiện tại nếu access token có `sid`.
- Ghi audit `PASSWORD_CHANGED`.

## GraphQL Types

Các payload quan trọng:

```graphql
type RegisterPayload {
  success: Boolean!
  message: String
}

type VerifyEmailPayload {
  success: Boolean!
  message: String
}

type AuthActionPayload {
  success: Boolean!
  message: String
  refreshTokenCookie: GatewayCookieInstruction
}

type LoginPayload {
  accessToken: String!
  refreshToken: String!
  refreshTokenExpiresAt: DateTime!
  refreshTokenCookie: GatewayCookieInstruction!
  user: UserType!
}

type UserType {
  userId: Long!
  email: String!
  validDate: DateTime
  status: Short!
}

input RegisterInput {
  email: String!
  password: String!
}

type SessionType {
  sessionId: Long!
  deviceName: String
  os: String
  browser: String
  ipAddress: String
  expiresAt: DateTime!
  createdAt: DateTime!
  lastSeenAt: DateTime
  revocationReason: String
  revokedAt: DateTime
  isCurrent: Boolean!
}

input GatewaySessionValidationInput {
  userId: Long!
  sessionId: Long!
}

type GatewaySessionValidationPayload {
  isValid: Boolean!
  userId: Long
  sessionId: Long
  status: Short
  expiresAt: DateTime
}
```

HotChocolate có thể expose tên scalar .NET khác nhau tùy schema generation. Nếu Gateway cần exact scalar name, hãy introspect live schema.

## Error Codes Thường Gặp

GraphQL error dùng `extensions.code`.

Validation và identity:

```text
IDENTIFIER_EXISTS
INVALID_EMAIL
WEAK_PASSWORD
INVALID_CREDENTIALS
ACCOUNT_NOT_FOUND
ACCOUNT_UNAVAILABLE
EMAIL_UNVERIFIED
UNAUTHENTICATED
FORBIDDEN
```

OTP và verification:

```text
INVALID_VERIFICATION_CODE
INVALID_OR_EXPIRED_VERIFICATION_CODE
INVALID_OR_EXPIRED_PASSWORD_RESET_CODE
OTP_COOLDOWN
OTP_RATE_LIMITED
OTP_RESEND_RATE_LIMITED
```

Login và token:

```text
LOGIN_RATE_LIMITED
INVALID_REFRESH_TOKEN
REFRESH_TOKEN_REUSE_DETECTED
```

Password/session:

```text
PASSWORD_UNCHANGED
INVALID_SESSION_ID
SESSION_NOT_FOUND
```

## Audit Actions

Các audit action hiện có:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
REFRESH_TOKEN_ROTATED
REFRESH_TOKEN_REUSE_DETECTED
REVOKED_REFRESH_TOKEN_USED
LOGOUT
LOGOUT_ALL
SESSION_REVOKED
OTP_RESENT
OTP_VERIFICATION_FAILURE
OTP_VERIFIED
PASSWORD_RESET
PASSWORD_CHANGED
```

Audit metadata gồm IP address, user agent và JSON data tùy event.

Ví dụ:

- Login failure có `identifier` và `reason`.
- Login success có `sessionId` và `identifier`.
- OTP event có `type` và `purpose`.
- Session revoke có `sessionId` và `isCurrentSession`.

## Lưu Ý Bảo Mật

- Không lưu raw refresh token.
- Không log raw refresh token, password, OTP, SMTP password, DB password hoặc JWT signing key.
- Refresh token phải rotate ở mọi lần refresh thành công.
- Dùng lại refresh token cũ của session đang active được coi là dấu hiệu compromise và revoke toàn bộ session.
- Dùng token của session đã revoke/expired chỉ bị reject, không revoke toàn account.
- Frontend không nên lưu refresh token trong localStorage hoặc state JavaScript đọc được.
- Gateway nên set refresh token cookie với `HttpOnly`, `Secure`, và `SameSite` theo config.
- Access token sống ngắn, frontend có thể giữ theo thiết kế Gateway, nhưng vẫn phải cân nhắc rủi ro XSS.
- Các subgraph khác không được tin identity header do browser gửi trực tiếp.

## Quy Trình Đăng Ký Chuẩn

```text
1. Client gửi name, gender, birthdate, location, email và password tới Gateway createUser.
2. Gateway route createUser sang SocialGraph qua Fusion.
3. SocialGraph tạo profile object và canonical Snowflake userId.
4. SocialGraph gọi Auth POST /internal/users với userId, email, password và X-Gateway-Secret; profile field vẫn nằm tại SocialGraph.
5. Auth tạo email identity unverified bằng đúng userId được truyền và lưu password hash.
6. Auth tạo verification OTP hash và gửi email nếu SMTP enabled.
7. Nếu Auth lỗi, SocialGraph xóa profile object vừa tạo và trả CreateUserPayload thất bại.
8. Nếu Auth thành công, SocialGraph gọi đồng thời Search `PUT /internal/search/indexes/{userId}` và Recommendation `PUT /internal/recommendation/users/{userId}/embedding` bằng cùng ID/correlation ID.
9. Search và Recommendation idempotent, best-effort; lỗi projection không rollback identity mà Auth đã chấp nhận.
10. Client gửi identifier + OTP qua Gateway verifyEmail.
11. Auth activate account.
12. Client có thể login.
```

## Quy Trình Login/Refresh Với Gateway

```text
1. Client gọi Gateway login.
2. Gateway gọi Auth login với email trong `identifier` và password.
3. Auth validate credential và tạo session.
4. Auth trả access token, refresh token, SET cookie instruction.
5. Gateway set refresh token cookie.
6. Gateway trả access token và user về client.
7. Client dùng access token cho protected operation.
8. Khi access token hết hạn, client gọi Gateway refresh.
9. Gateway đọc refresh token cookie và gọi Auth refreshToken.
10. Auth rotate refresh token và trả SET instruction mới.
11. Gateway update cookie và trả access token mới.
```

## Quy Trình Logout Với Gateway

```text
logout:
  Gateway đọc refresh cookie
  Gateway gọi Auth logout(refreshToken)
  Gateway clear cookie

logoutAll:
  Gateway gọi Auth logoutAll với bearer access token
  Gateway clear cookie

logoutSession:
  Gateway gọi Auth logoutSession(sessionId)
  Nếu response refreshTokenCookie.operation == CLEAR thì clear cookie hiện tại
  Nếu refreshTokenCookie null thì không đụng cookie hiện tại
```

## Testing Notes

Contract test tự động `dotnet test fakebookAuth.sln` và E2E runner rộng hơn cover:

- Gateway `createUser` qua SocialGraph trong khi Auth không nhận profile field, sau đó verify email
- internal create bằng custom userId cho SocialGraph
- login
- refresh token rotation
- refresh token reuse detection
- reject refresh token của session đã revoke
- logout
- logoutAll
- logoutSession
- mySessions
- mySessionHistory
- password reset OTP limit
- password reset thành công
- change password
- login rate limit
- OTP resend limit
- cookie instruction contract
- internal `validateGatewaySession` contract
- reject sai Payment secret, đọc Premium state, update `validDate` idempotent và retry không rút ngắn validity
- reject access token của session đã revoke
- multi-device session behavior
- Gateway proxy login/refresh/logout cookie behavior

Local E2E runner nằm tại `scripts/auth-gateway-e2e.ps1`. Truyền `-PaymentSecret` cùng giá trị với Auth `Payment__InternalSharedSecret`. Script kiểm tra integration Auth/SocialGraph/Gateway/Payment và không print OTP, access token, refresh token hay cookie value. Test project cố định kiểm tra Auth schema/internal payload/JWT email-only và không có phone/profile field, UTC Payment date và database artifact mà không cần hạ tầng ngoài.

## Contract Nội bộ với Backend-Payment

Authentication sở hữu `fb.id_user.valid_date`; Payment sở hữu toàn bộ order, provider transaction và outbox data. Cấu hình `Payment__InternalSharedSecret` độc lập với `Gateway__InternalSharedSecret`.

Backend-Payment gọi trực tiếp Auth bằng `X-Payment-Secret`:

```graphql
query PaymentPremiumState($userId: ID!) {
  paymentPremiumState(userId: $userId) { userId validDate }
}

mutation SetPaymentValidDate($input: SetPaymentValidDateInput!) {
  setPaymentValidDate(input: $input) { userId validDate }
}
```

Hai operation so sánh secret constant-time. `setPaymentValidDate` idempotent và không bao giờ rút ngắn validity vì persistence dùng `GREATEST(COALESCE(valid_date, '-infinity'), @ValidDate)`. Gateway schema extensions phải đánh dấu cả hai field là `@internal`; `UserType.validDate` vẫn có trên user projection.

## Lệnh Local

Build:

```powershell
dotnet build .\fakebookAuth\fakebookAuth.csproj --no-restore
```

Run:

```powershell
dotnet run --project .\fakebookAuth\fakebookAuth.csproj
```

Ví dụ chạy bằng environment variables:

```powershell
$env:ConnectionStrings__DefaultConnection="Host=localhost;Port=5432;Database=fakebook;Username=postgres;Password=..."
$env:Jwt__SigningKey="at-least-32-bytes-long-signing-key"
$env:Smtp__Enabled="false"
dotnet run --project .\fakebookAuth\fakebookAuth.csproj
```

GraphQL endpoint:

```text
http://localhost:<port>/graphql
```

## Việc Nên Làm Tiếp

- Tạo test project cố định.
- Thêm migration system chính thức nếu project phát triển thêm.
- Giữ exported federation schema và Gateway composition artifacts đồng bộ khi Auth schema thay đổi.
- Thêm roles/permissions và MFA khi có requirement sản phẩm.
- Thêm `appsettings.example.json` và loại bỏ real secrets khỏi các file tracked.
