-- Identity & Access domain (PostgreSQL) cho Fakebook
-- Đã kết hợp tối ưu: BigInt PKs (Snowflake ID), JSONB mặc định, và quản lý Session/Verification thiết bị chi tiết.

CREATE SCHEMA IF NOT EXISTS fb;
SET search_path TO fb;

-- 1. Bảng id_user (tài khoản định danh)
CREATE TABLE id_user (
                         user_id          bigint PRIMARY KEY,
                         email            text UNIQUE,
                         phone            text UNIQUE,
                         valid_date       timestamptz,
                         status           smallint NOT NULL DEFAULT 4, -- 1=active, 2=disabled, 3=deleted, 4=unverified
                         created_at       timestamptz NOT NULL DEFAULT now(),
                         updated_at       timestamptz NOT NULL DEFAULT now()
);

-- 2. Bảng id_credential (Phương thức đăng nhập)
CREATE TABLE id_credential (
                               credential_id    bigint PRIMARY KEY,
                               user_id          bigint NOT NULL REFERENCES id_user(user_id) ON DELETE CASCADE,
                               provider         smallint NOT NULL, -- 1=password, 2=oauth, 3=sso
                               secret_hash      text,
                               created_at       timestamptz NOT NULL DEFAULT now(),
                               last_used_at     timestamptz
);

-- 3. Bảng id_session (Quản lý phiên & Nơi bạn đã đăng nhập)
CREATE TABLE id_session (
                            session_id       bigint PRIMARY KEY,
                            user_id          bigint NOT NULL REFERENCES id_user(user_id) ON DELETE CASCADE,
                            refresh_token    text NOT NULL, -- Stores SHA-256 hash of the refresh token, not the raw token
                            device_name      text,          -- VD: 'iPhone 15 Pro Max'
                            os               text,          -- VD: 'iOS 17'
                            browser          text,          -- VD: 'Safari'
                            ip_address       inet,
                            expires_at       timestamptz NOT NULL,
                            created_at       timestamptz NOT NULL DEFAULT now(),
                            last_seen_at     timestamptz NOT NULL DEFAULT now(),
                            revocation_reason text,
                            revoked_at       timestamptz
);

CREATE TABLE id_session_refresh_token (
                            token_hash       text PRIMARY KEY,
                            session_id       bigint NOT NULL REFERENCES id_session(session_id) ON DELETE CASCADE,
                            expires_at       timestamptz NOT NULL,
                            created_at       timestamptz NOT NULL DEFAULT now(),
                            replaced_at      timestamptz,
                            reuse_detected_at timestamptz
);

-- 4. Bảng id_verification (Mã xác thực, OTP, Quên mật khẩu)
CREATE TABLE id_verification (
                                 verification_id  bigint PRIMARY KEY,
                                 user_id          bigint NOT NULL REFERENCES id_user(user_id) ON DELETE CASCADE,
                                 type             smallint NOT NULL, -- 1=email_verify, 2=phone_otp, 3=password_reset
                                 token_hash       text NOT NULL,
                                 is_used          boolean NOT NULL DEFAULT false,
                                 expires_at       timestamptz NOT NULL,
                                 created_at       timestamptz NOT NULL DEFAULT now()
);

-- 5. Bảng id_role (Nhóm quyền quản trị)
CREATE TABLE id_role (
                         role_id          bigint PRIMARY KEY,
                         code             text NOT NULL UNIQUE,
                         name             text NOT NULL,
                         created_at       timestamptz NOT NULL DEFAULT now()
);

-- 6. Bảng id_permission (Quyền chi tiết)
CREATE TABLE id_permission (
                               permission_id    bigint PRIMARY KEY,
                               code             text NOT NULL UNIQUE,
                               name             text NOT NULL
);

-- 7. Bảng id_role_permission (Liên kết Role - Permission)
CREATE TABLE id_role_permission (
                                    role_id          bigint NOT NULL REFERENCES id_role(role_id) ON DELETE CASCADE,
                                    permission_id    bigint NOT NULL REFERENCES id_permission(permission_id) ON DELETE CASCADE,
                                    PRIMARY KEY (role_id, permission_id)
);

-- 8. Bảng id_user_role (Liên kết User - Role)
CREATE TABLE id_user_role (
                              user_id          bigint NOT NULL REFERENCES id_user(user_id) ON DELETE CASCADE,
                              role_id          bigint NOT NULL REFERENCES id_role(role_id) ON DELETE CASCADE,
                              PRIMARY KEY (user_id, role_id)
);

-- 9. Bảng id_mfa_method (Xác thực đa yếu tố)
CREATE TABLE id_mfa_method (
                               mfa_id           bigint PRIMARY KEY,
                               user_id          bigint NOT NULL REFERENCES id_user(user_id) ON DELETE CASCADE,
                               method           smallint NOT NULL, -- 1=totp, 2=sms, 3=email
                               secret           text NOT NULL,
                               is_enabled       boolean NOT NULL DEFAULT false,
                               created_at       timestamptz NOT NULL DEFAULT now()
);

-- 10. Bảng id_audit_log (Nhật ký hệ thống & bảo mật)
CREATE TABLE id_audit_log (
                              audit_id         bigint PRIMARY KEY,
                              user_id          bigint REFERENCES id_user(user_id) ON DELETE SET NULL,
                              action           text NOT NULL,
                              ip_address       inet,
                              user_agent       text,
                              created_at       timestamptz NOT NULL DEFAULT now(),
                              data             jsonb NOT NULL DEFAULT '{}'::jsonb
);

-------------------------------------------------------------------------
-- CHỈ MỤC (INDEXES)
-------------------------------------------------------------------------

-- Lấy danh sách thiết bị/phiên đang hoạt động nhanh chóng
CREATE INDEX id_session_user_idx ON id_session (user_id, expires_at);

CREATE INDEX id_session_refresh_token_session_idx
    ON id_session_refresh_token (session_id, created_at DESC);

CREATE INDEX id_session_refresh_token_replaced_idx
    ON id_session_refresh_token (token_hash)
    WHERE replaced_at IS NOT NULL;

-- Lịch sử bảo mật: Thường xuyên query các log MỚI NHẤT của 1 user
CREATE INDEX id_audit_user_time_idx ON id_audit_log (user_id, created_at DESC);

-- Login rate limit: find the latest successful login and count recent failed logins by identifier.
CREATE INDEX id_audit_login_success_identifier_time_idx
    ON id_audit_log ((data ->> 'identifier'), created_at DESC, ip_address)
    WHERE action = 'LOGIN_SUCCESS';

CREATE INDEX id_audit_login_failure_identifier_time_idx
    ON id_audit_log ((data ->> 'identifier'), created_at DESC, ip_address)
    WHERE action = 'LOGIN_FAILURE';

CREATE INDEX id_audit_otp_user_action_type_time_idx
    ON id_audit_log (user_id, action, (data ->> 'type'), created_at DESC)
    WHERE action IN ('OTP_RESENT', 'OTP_VERIFICATION_FAILURE');

-- Truy vấn verify token cực nhanh lúc user submit OTP
CREATE INDEX id_verification_token_idx ON id_verification (token_hash);

-- (Tùy chọn) B-Tree index chuẩn cho các trường định danh dùng để login
CREATE INDEX id_user_email_idx ON id_user (email);
CREATE INDEX id_user_phone_idx ON id_user (phone);
