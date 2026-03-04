-- Sprint 5 schema updates (Team23)

-- 1) Password reset tokens (hashed token, single-use, expires)
CREATE TABLE IF NOT EXISTS PasswordResetTokens (
  TokenID INT AUTO_INCREMENT PRIMARY KEY,
  UserID INT NOT NULL,
  TokenHash VARCHAR(255) NOT NULL,
  ExpiresAt DATETIME NOT NULL,
  UsedAt DATETIME NULL,
  CreatedAt DATETIME NOT NULL,
  RequestIP VARCHAR(64) NULL,
  INDEX idx_prt_user (UserID),
  INDEX idx_prt_expires (ExpiresAt),
  UNIQUE KEY uniq_token_hash (TokenHash)
);

-- 2) Password change log for sponsor reporting
CREATE TABLE IF NOT EXISTS PasswordChangeLog (
  LogID INT AUTO_INCREMENT PRIMARY KEY,
  OrganizationID INT NULL,
  ActorUserID INT NOT NULL,
  TargetUserID INT NOT NULL,
  EventType VARCHAR(32) NOT NULL, -- change / reset / rehash
  EventTime DATETIME NOT NULL,
  ActorIP VARCHAR(64) NULL,
  INDEX idx_pcl_org (OrganizationID),
  INDEX idx_pcl_time (EventTime),
  INDEX idx_pcl_target (TargetUserID)
);

-- 3) Optional: ensure PointAdjustments exists (your code tries to insert into it)
CREATE TABLE IF NOT EXISTS PointAdjustments (
  AdjustmentID INT AUTO_INCREMENT PRIMARY KEY,
  OrganizationID INT NOT NULL,
  AdjustedByUName VARCHAR(80) NOT NULL,
  DriverUName VARCHAR(80) NOT NULL,
  AdjustmentPoints INT NOT NULL,
  AdjustmentReason VARCHAR(255) NOT NULL,
  DateAdjusted DATETIME NOT NULL,
  INDEX idx_pa_org (OrganizationID),
  INDEX idx_pa_date (DateAdjusted)
);